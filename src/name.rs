// Copyright 2015 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use super::cert::{EndEntityOrCA, parse_cert};
use super::der;
use super::Error;
use super::input::{Input, Reader};


// Verify that the given end-entity cert, which is assumed to have been already
// validated with `verify_cert`, is valid for the given hostname. `hostname` is
// assumed to a normalized ASCII (punycode if non-ASCII) DNS name.
pub fn verify_cert_dns_name(cert_der: Input, dns_name: Input)
                            -> Result<(), Error> {
    let cert = try!(parse_cert(cert_der, EndEntityOrCA::EndEntity));

    if !is_valid_reference_dns_id(dns_name) {
        return Err(Error::InvalidReferenceName);
    }

    iterate_names(cert.subject, cert.subject_alt_name,
                  Err(Error::CertNotValidForName), &|name| {
        match name {
            GeneralName::DNSName(presented_id) => {
                match presented_dns_id_matches_reference_dns_id(
                        presented_id, IDRole::ReferenceID, dns_name) {
                    Some(true) => { return NameIteration::Stop(Ok(())); },
                    Some(false) => (),
                    None => { return NameIteration::Stop(Err(Error::BadDER)); },
                }
            },
            _ => ()
        }
        NameIteration::KeepGoing
    })
}

#[derive(Clone, Copy)]
enum NameIteration {
    KeepGoing,
    Stop(Result<(), Error>)
}

fn iterate_names(subject: Input, subject_alt_name: Option<Input>,
                 result_if_never_stopped_early: Result<(), Error>,
                 f: &Fn(GeneralName) -> NameIteration) -> Result<(), Error> {
    match subject_alt_name {
        Some(subject_alt_name) => {
            let mut subject_alt_name = Reader::new(subject_alt_name);
            // https://bugzilla.mozilla.org/show_bug.cgi?id=1143085: An empty
            // subjectAltName is not legal, but some certificates have an empty
            // subjectAltName. Since we don't support CN-IDs, the certificate
            // will be rejected either way, but checking `at_end` before
            // attempting to parse the first entry allows us to return a better
            // error code.
            while !subject_alt_name.at_end() {
                let name = try!(general_name(&mut subject_alt_name));
                match f(name) {
                    NameIteration::Stop(result) => { return result; },
                    NameIteration::KeepGoing => ()
                }
            }
        },
        None => ()
    }

    match f(GeneralName::DirectoryName(subject)) {
        NameIteration::Stop(result) => result,
        NameIteration::KeepGoing => result_if_never_stopped_early
    }
}

// It is *not* valid to derive `Eq`, `PartialEq, etc. for this type. In
// particular, for the types of `GeneralName`s that we don't understand, we
// don't even store the value. Also, the meaning of a `GeneralName` in a name
// constraint is different than the meaning of the identically-represented
// `GeneralName` in other contexts.
enum GeneralName<'a> {
    DNSName(Input<'a>),
    DirectoryName(Input<'a>),
    IPAddress(Input<'a>),

    // The value is the `tag & ~(der::CONTEXT_SPECIFIC | der::CONSTRUCTED)` so
    // that the name constraint checking matches tags regardless of whether
    // those bits are set.
    Unsupported(u8)
}

fn general_name<'a>(input: &mut Reader<'a>) -> Result<GeneralName<'a>, Error> {
    use der::{CONSTRUCTED, CONTEXT_SPECIFIC};
    const OTHER_NAME_TAG: u8 = CONTEXT_SPECIFIC | CONSTRUCTED | 0;
    const RFC822_NAME_TAG: u8 = CONTEXT_SPECIFIC | 1;
    const DNS_NAME_TAG: u8 = CONTEXT_SPECIFIC | 2;
    const X400_ADDRESS_TAG : u8 = CONTEXT_SPECIFIC | CONSTRUCTED | 3;
    const DIRECTORY_NAME_TAG: u8 = CONTEXT_SPECIFIC | CONSTRUCTED | 4;
    const EDI_PARTY_NAME_TAG: u8 = CONTEXT_SPECIFIC | CONSTRUCTED | 5;
    const UNIFORM_RESOURCE_IDENTIFIER_TAG: u8 = CONTEXT_SPECIFIC | 6;
    const IP_ADDRESS_TAG: u8 = CONTEXT_SPECIFIC | 7;
    const REGISTERED_ID_TAG: u8 = CONTEXT_SPECIFIC | 8;

    let (tag, value) = try!(der::read_tag_and_get_input(input));
    let name = match tag {
        DNS_NAME_TAG => GeneralName::DNSName(value),
        DIRECTORY_NAME_TAG => GeneralName::DirectoryName(value),
        IP_ADDRESS_TAG => GeneralName::IPAddress(value),

        OTHER_NAME_TAG |
        RFC822_NAME_TAG |
        X400_ADDRESS_TAG |
        EDI_PARTY_NAME_TAG |
        UNIFORM_RESOURCE_IDENTIFIER_TAG |
        REGISTERED_ID_TAG =>
            GeneralName::Unsupported(tag & !(CONTEXT_SPECIFIC | CONSTRUCTED)),

        _ => return Err(Error::BadDER)
    };
    Ok(name)
}

// We do not distinguish between a syntactically-invalid presented_dns_id and
// one that is syntactically valid but does not match reference_dns_id; in both
// cases, the result is false.
//
// We assume that both presented_dns_id and reference_dns_id are encoded in
// such a way that US-ASCII (7-bit) characters are encoded in one byte and no
// encoding of a non-US-ASCII character contains a code point in the range
// 0-127. For example, UTF-8 is OK but UTF-16 is not.
//
// RFC6125 says that a wildcard label may be of the form <x>*<y>.<DNSID>, where
// <x> and/or <y> may be empty. However, NSS requires <y> to be empty, and we
// follow NSS's stricter policy by accepting wildcards only of the form
// <x>*.<DNSID>, where <x> may be empty.
//
// An relative presented DNS ID matches both an absolute reference ID and a
// relative reference ID. Absolute presented DNS IDs are not supported:
//
//      Presented ID   Reference ID  Result
//      -------------------------------------
//      example.com    example.com   Match
//      example.com.   example.com   Mismatch
//      example.com    example.com.  Match
//      example.com.   example.com.  Mismatch
//
// There are more subtleties documented inline in the code.
//
// Name constraints ///////////////////////////////////////////////////////////
//
// This is all RFC 5280 has to say about DNSName constraints:
//
//     DNS name restrictions are expressed as host.example.com.  Any DNS
//     name that can be constructed by simply adding zero or more labels to
//     the left-hand side of the name satisfies the name constraint.  For
//     example, www.host.example.com would satisfy the constraint but
//     host1.example.com would not.
//
// This lack of specificity has lead to a lot of uncertainty regarding
// subdomain matching. In particular, the following questions have been
// raised and answered:
//
//     Q: Does a presented identifier equal (case insensitive) to the name
//        constraint match the constraint? For example, does the presented
//        ID "host.example.com" match a "host.example.com" constraint?
//     A: Yes. RFC5280 says "by simply adding zero or more labels" and this
//        is the case of adding zero labels.
//
//     Q: When the name constraint does not start with ".", do subdomain
//        presented identifiers match it? For example, does the presented
//        ID "www.host.example.com" match a "host.example.com" constraint?
//     A: Yes. RFC5280 says "by simply adding zero or more labels" and this
//        is the case of adding more than zero labels. The example is the
//        one from RFC 5280.
//
//     Q: When the name constraint does not start with ".", does a
//        non-subdomain prefix match it? For example, does "bigfoo.bar.com"
//        match "foo.bar.com"? [4]
//     A: No. We interpret RFC 5280's language of "adding zero or more labels"
//        to mean that whole labels must be prefixed.
//
//     (Note that the above three scenarios are the same as the RFC 6265
//     domain matching rules [0].)
//
//     Q: Is a name constraint that starts with "." valid, and if so, what
//        semantics does it have? For example, does a presented ID of
//        "www.example.com" match a constraint of ".example.com"? Does a
//        presented ID of "example.com" match a constraint of ".example.com"?
//     A: This implementation, NSS[1], and SChannel[2] all support a
//        leading ".", but OpenSSL[3] does not yet. Amongst the
//        implementations that support it, a leading "." is legal and means
//        the same thing as when the "." is omitted, EXCEPT that a
//        presented identifier equal (case insensitive) to the name
//        constraint is not matched; i.e. presented DNSName identifiers
//        must be subdomains. Some CAs in Mozilla's CA program (e.g. HARICA)
//        have name constraints with the leading "." in their root
//        certificates. The name constraints imposed on DCISS by Mozilla also
//        have the it, so supporting this is a requirement for backward
//        compatibility, even if it is not yet standardized. So, for example, a
//        presented ID of "www.example.com" matches a constraint of
//        ".example.com" but a presented ID of "example.com" does not.
//
//     Q: Is there a way to prevent subdomain matches?
//     A: Yes.
//
//        Some people have proposed that dNSName constraints that do not
//        start with a "." should be restricted to exact (case insensitive)
//        matches. However, such a change of semantics from what RFC5280
//        specifies would be a non-backward-compatible change in the case of
//        permittedSubtrees constraints, and it would be a security issue for
//        excludedSubtrees constraints.
//
//        However, it can be done with a combination of permittedSubtrees and
//        excludedSubtrees, e.g. "example.com" in permittedSubtrees and
//        ".example.com" in excudedSubtrees.
//
//     Q: Are name constraints allowed to be specified as absolute names?
//        For example, does a presented ID of "example.com" match a name
//        constraint of "example.com." and vice versa.
//     A: Absolute names are not supported as presented IDs or name
//        constraints. Only reference IDs may be absolute.
//
//     Q: Is "" a valid DNSName constraints? If so, what does it mean?
//     A: Yes. Any valid presented DNSName can be formed "by simply adding zero
//        or more labels to the left-hand side" of "". In particular, an
//        excludedSubtrees DNSName constraint of "" forbids all DNSNames.
//
//     Q: Is "." a valid DNSName constraints? If so, what does it mean?
//     A: No, because absolute names are not allowed (see above).
//
// [0] RFC 6265 (Cookies) Domain Matching rules:
//     http://tools.ietf.org/html/rfc6265#section-5.1.3
// [1] NSS source code:
//     https://mxr.mozilla.org/nss/source/lib/certdb/genname.c?rev=2a7348f013cb#1209
// [2] Description of SChannel's behavior from Microsoft:
//     http://www.imc.org/ietf-pkix/mail-archive/msg04668.html
// [3] Proposal to add such support to OpenSSL:
//     http://www.mail-archive.com/openssl-dev%40openssl.org/msg36204.html
//     https://rt.openssl.org/Ticket/Display.html?id=3562
// [4] Feedback on the lack of clarify in the definition that never got
//     incorporated into the spec:
//     https://www.ietf.org/mail-archive/web/pkix/current/msg21192.html
fn presented_dns_id_matches_reference_dns_id(presented_dns_id: Input,
                                             reference_dns_id_role: IDRole,
                                             reference_dns_id: Input)
                                             -> Option<bool> {
    if !is_valid_dns_id(presented_dns_id, IDRole::PresentedID,
                        AllowWildcards::Yes) {
        return None;
    }

    if !is_valid_dns_id(reference_dns_id, reference_dns_id_role,
                        AllowWildcards::No) {
        return None;
    }

    let mut presented = Reader::new(presented_dns_id);
    let mut reference = Reader::new(reference_dns_id);

    match reference_dns_id_role {
        IDRole::ReferenceID => (),

        IDRole::NameConstraint
            if presented_dns_id.len() > reference_dns_id.len() => {

            if reference_dns_id.len() == 0 {
                // An empty constraint matches everything.
                return Some(true);
            }

            // If the reference ID starts with a dot then skip the prefix of
            // the presented ID and start the comparison at the position of
            // that dot. Examples:
            //
            //                                       Matches     Doesn't Match
            //     -----------------------------------------------------------
            //       original presented ID:  www.example.com    badexample.com
            //                     skipped:  www                ba
            //     presented ID w/o prefix:     .example.com      dexample.com
            //                reference ID:     .example.com      .example.com
            //
            // If the reference ID does not start with a dot then we skip
            // the prefix of the presented ID but also verify that the
            // prefix ends with a dot. Examples:
            //
            //                                       Matches     Doesn't Match
            //     -----------------------------------------------------------
            //       original presented ID:  www.example.com    badexample.com
            //                     skipped:  www                ba
            //                 must be '.':     .                 d
            //     presented ID w/o prefix:      example.com       example.com
            //                reference ID:      example.com       example.com
            //
            if reference.peek(b'.') {
                if presented.skip(presented_dns_id.len() -
                                  reference_dns_id.len()).is_none() {
                    unreachable!();
                }
            } else {
                if presented.skip(presented_dns_id.len() -
                                 reference_dns_id.len() - 1).is_none() {
                    unreachable!();
                }
                if presented.read_byte() != Some(b'.') {
                    return Some(false);
                }
            }
        },

        IDRole::NameConstraint => (),

        IDRole::PresentedID => unreachable!()
    }

    // Only allow wildcard labels that consist only of '*'.
    if presented.peek(b'*') {
        if presented.skip(1).is_none() {
            unreachable!();
        }
        loop {
            match reference.read_byte() {
                None => { return Some(false); },
                Some(b'.') => { break; },
                Some(..) => (),
            }
        }
    }

    loop {
        let presented_byte =
            match (presented.read_byte(), reference.read_byte()) {
                (Some(p), Some(r)) if p == r => p,
                _ => { return Some(false); }
            };

        if presented.at_end() {
            // Don't allow presented IDs to be absolute.
            if presented_byte == b'.' {
                return None;
            }
            break;
        }
    }

    // Allow a relative presented DNS ID to match an absolute reference DNS ID,
    // unless we're matching a name constraint.
    if !reference.at_end() {
        if reference_dns_id_role != IDRole::NameConstraint {
            match reference.read_byte() {
                Some(b'.') => (),
                _ => { return Some(false); }
            };
        }
        if !reference.at_end() {
            return Some(false);
        }
    }

    assert!(presented.at_end());
    assert!(reference.at_end());

    return Some(true);
}

#[derive(PartialEq)]
enum AllowWildcards {
    No,
    Yes
}

#[derive(Clone, Copy, PartialEq)]
enum IDRole {
  ReferenceID,
  PresentedID,
  NameConstraint,
}

fn is_valid_reference_dns_id(hostname: Input) -> bool {
    is_valid_dns_id(hostname, IDRole::ReferenceID, AllowWildcards::No)
}

// https://tools.ietf.org/html/rfc5280#section-4.2.1.6:
//
//   When the subjectAltName extension contains a domain name system
//   label, the domain name MUST be stored in the dNSName (an IA5String).
//   The name MUST be in the "preferred name syntax", as specified by
//   Section 3.5 of [RFC1034] and as modified by Section 2.1 of
//   [RFC1123].
//
// https://bugzilla.mozilla.org/show_bug.cgi?id=1136616: As an exception to the
// requirement above, underscores are also allowed in names for compatibility.
fn is_valid_dns_id(hostname: Input, id_role: IDRole,
                   allow_wildcards: AllowWildcards) -> bool {
    if hostname.len() > 255 {
        return false;
    }

    let mut input = Reader::new(hostname);

    if id_role == IDRole::NameConstraint && input.at_end() {
        return true;
    }

    let mut dot_count = 0;
    let mut label_length = 0;
    let mut label_is_all_numeric = false;
    let mut label_ends_with_hyphen = false;

    // Only presented IDs are allowed to have wildcard labels. And, like
    // Chromium, be stricter than RFC 6125 requires by insisting that a
    // wildcard label consist only of '*'.
    let is_wildcard = allow_wildcards == AllowWildcards::Yes &&
                     input.peek(b'*');
    let mut is_first_byte = !is_wildcard;
    if is_wildcard {
        if input.read_byte() != Some(b'*') ||
           input.read_byte() != Some(b'.') {
            return false;
        }
        dot_count += 1;
    }

    loop {
        const MAX_LABEL_LENGTH: usize = 63;

        match input.read_byte() {
            Some(b'-') => {
                if label_length == 0 {
                    return false; // Labels must not start with a hyphen.
                }
                label_is_all_numeric = false;
                label_ends_with_hyphen = true;
                label_length += 1;
                if label_length > MAX_LABEL_LENGTH {
                    return false;
                }
            },

            Some(b'0'...b'9') => {
                if label_length == 0 {
                    label_is_all_numeric = true;
                }
                label_ends_with_hyphen = false;
                label_length += 1;
                if label_length > MAX_LABEL_LENGTH {
                    return false;
                }
            },

            Some(b'a'...b'z') | Some(b'A'...b'Z') | Some(b'_') => {
                label_is_all_numeric = false;
                label_ends_with_hyphen = false;
                label_length += 1;
                if label_length > MAX_LABEL_LENGTH {
                    return false;
                }
            },

            Some(b'.') => {
                dot_count += 1;
                if label_length == 0 &&
                   (id_role != IDRole::NameConstraint || !is_first_byte) {
                  return false;
                }
                if label_ends_with_hyphen {
                  return false; // Labels must not end with a hyphen.
                }
                label_length = 0;
            },

            _ => { return false; }
        }
        is_first_byte = false;

        if input.at_end() {
            break;
        }
    }

    // Only reference IDs, not presented IDs or name constraints, may be
    // absolute.
    if label_length == 0 && id_role != IDRole::ReferenceID {
        return false;
    }

    if label_ends_with_hyphen {
        return false; // Labels must not end with a hyphen.
    }

    if label_is_all_numeric {
        return false; // Last label must not be all numeric.
    }

    if is_wildcard {
        // If the DNS ID ends with a dot, the last dot signifies an absolute ID.
        let label_count = if label_length == 0 { dot_count }
                          else { dot_count + 1 };

        // Like NSS, require at least two labels to follow the wildcard label.
        // TODO: Allow the TrustDomain to control this on a per-eTLD+1 basis,
        // similar to Chromium. Even then, it might be better to still enforce
        // that there are at least two labels after the wildcard.
        if label_count < 3 {
            return false;
        }

        // XXX: RFC6125 says that we shouldn't accept wildcards within an IDN
        // A-Label. The consequence of this is that we effectively discriminate
        // against users of languages that cannot be encoded with ASCII.
        let mut maybe_idn = Reader::new(hostname);
        if maybe_idn.read_byte() == Some(b'x') &&
           maybe_idn.read_byte() == Some(b'n') &&
           maybe_idn.read_byte() == Some(b'-') &&
           maybe_idn.read_byte() == Some(b'-') {
            return false;
        }
    }

    true
}
