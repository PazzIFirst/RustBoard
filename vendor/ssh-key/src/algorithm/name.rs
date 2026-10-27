use alloc::string::String;
use core::str::{self, FromStr};
use encoding::LabelError;

/// The suffix added to the `name` in a `name@domainname` algorithm string identifier.
const CERT_STR_SUFFIX: &str = "-cert-v01";

/// According to [RFC4251 § 6], algorithm names are ASCII strings that are at most 64
/// characters long.
///
/// [RFC4251 § 6]: https://www.rfc-editor.org/rfc/rfc4251.html#section-6
const MAX_ALGORITHM_NAME_LEN: usize = 64;

/// The maximum length of the certificate string identifier is [`MAX_ALGORITHM_NAME_LEN`] +
/// `"-cert-v01".len()` (the certificate identifier is obtained by inserting `"-cert-v01"` in the
/// algorithm name).
const MAX_CERT_STR_LEN: usize = MAX_ALGORITHM_NAME_LEN + CERT_STR_SUFFIX.len();

/// A string representing an additional algorithm name in the `name@domainname` format (see
/// [RFC4251 § 6]).
///
/// Additional algorithm names must be non-empty printable ASCII strings no longer than 64
/// characters.
///
/// This also provides a `name-cert-v01@domainnname` string identifier for the corresponding
/// OpenSSH certificate format, derived from the specified `name@domainname` string.
///
/// NOTE: RFC4251 specifies additional validation criteria for algorithm names, but we do not
/// implement all of them here.
///
/// [RFC4251 § 6]: https://www.rfc-editor.org/rfc/rfc4251.html#section-6
#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct AlgorithmName {
    /// The string identifier which corresponds to this algorithm.
    id: String,
}

impl AlgorithmName {
    /// Create a new algorithm identifier.
    ///
    /// # Errors
    /// Returns [`LabelError`] in the event the identifier is invalid.
    pub fn new(id: impl Into<String>) -> Result<Self, LabelError> {
        let id = id.into();
        validate_algorithm_id(&id, MAX_ALGORITHM_NAME_LEN)?;
        split_algorithm_id(&id)?;
        Ok(Self { id })
    }

    /// Get the string identifier which corresponds to this algorithm name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.id
    }

    /// Get the string identifier which corresponds to the OpenSSH certificate format.
    #[must_use]
    #[allow(clippy::missing_panics_doc, reason = "should not panic")]
    pub fn certificate_type(&self) -> String {
        let (name, domain) = split_algorithm_id(&self.id).expect("format checked in constructor");
        format!("{name}{CERT_STR_SUFFIX}@{domain}")
    }

    /// Create a new [`AlgorithmName`] from an OpenSSH certificate format string identifier.
    ///
    /// # Errors
    /// Returns [`LabelError`] in the event the identifier is invalid.
    pub fn from_certificate_type(id: &str) -> Result<Self, LabelError> {
        validate_algorithm_id(id, MAX_CERT_STR_LEN)?;

        // Derive the algorithm name from the certificate format string identifier:
        let (name, domain) = split_algorithm_id(id)?;
        let name = name
            .strip_suffix(CERT_STR_SUFFIX)
            .ok_or_else(|| LabelError::new(id))?;

        // Re-validate the derived `name@domainname` identifier. In particular this
        // rejects an empty `name` (e.g. `-cert-v01@example.com`) instead of
        // constructing a value which would later panic in `certificate_type`.
        Self::new(format!("{name}@{domain}"))
    }
}

impl FromStr for AlgorithmName {
    type Err = LabelError;

    fn from_str(id: &str) -> Result<Self, LabelError> {
        Self::new(id)
    }
}

/// Check if the length of `id` is at most `n`, and that `id` consists only of
/// printable, non-whitespace ASCII characters.
fn validate_algorithm_id(id: &str, n: usize) -> Result<(), LabelError> {
    if id.len() > n || !id.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(LabelError::new(id));
    }

    Ok(())
}

/// Split a `name@domainname` algorithm string identifier into `(name, domainname)`.
fn split_algorithm_id(id: &str) -> Result<(&str, &str), LabelError> {
    let (name, domain) = id.split_once('@').ok_or_else(|| LabelError::new(id))?;

    // TODO: validate name and domain_name according to the criteria from RFC4251
    if name.is_empty() || domain.is_empty() || domain.contains('@') {
        return Err(LabelError::new(id));
    }

    Ok((name, domain))
}

#[cfg(test)]
mod tests {
    use super::{AlgorithmName, CERT_STR_SUFFIX, MAX_CERT_STR_LEN};
    use alloc::string::String;

    fn cert_id(name: &str, domain: &str) -> String {
        format!("{name}{CERT_STR_SUFFIX}@{domain}")
    }

    #[test]
    fn from_certificate_type_rejects_empty_name() {
        // `-cert-v01@example.com` used to produce an `AlgorithmName` with the
        // invalid internal identifier `@example.com`, which later panicked in
        // `certificate_type`.
        assert!(AlgorithmName::from_certificate_type("-cert-v01@example.com").is_err());
        assert!(AlgorithmName::new("@example.com").is_err());
    }

    #[test]
    fn from_certificate_type_rejects_invalid_identifiers() {
        assert!(AlgorithmName::from_certificate_type("custom@example.com").is_err());
        assert!(AlgorithmName::from_certificate_type("custom-cert-v01@").is_err());
        assert!(AlgorithmName::from_certificate_type("@example.com").is_err());
        assert!(AlgorithmName::from_certificate_type("custom-cert-v01@example.com@extra").is_err());
        assert!(AlgorithmName::from_certificate_type("é-cert-v01@example.com").is_err());
    }

    #[test]
    fn certificate_type_roundtrip() {
        let name = AlgorithmName::new("custom@example.com").unwrap();
        assert_eq!(name.certificate_type(), "custom-cert-v01@example.com");

        let parsed = AlgorithmName::from_certificate_type(&name.certificate_type()).unwrap();
        assert_eq!(parsed, name);
        assert_eq!(parsed.certificate_type(), name.certificate_type());
    }

    #[test]
    fn algorithm_name_rejects_whitespace_and_control_characters() {
        for id in [
            "foo bar@example.com",
            "foo\tbar@example.com",
            "foo\nbar@example.com",
            "foo\x7fbar@example.com",
            "foo@example .com",
        ] {
            assert!(AlgorithmName::new(id).is_err(), "accepted {id:?}");
        }

        for id in [
            "foo bar-cert-v01@example.com",
            "foo\tbar-cert-v01@example.com",
            "foo\x7fbar-cert-v01@example.com",
        ] {
            assert!(
                AlgorithmName::from_certificate_type(id).is_err(),
                "accepted {id:?}"
            );
        }

        // Printable punctuation and the `@` separator remain valid.
        assert!(AlgorithmName::new("foo-bar_baz.qux@example.com").is_ok());
    }

    #[test]
    fn certificate_type_length_boundary() {
        // `MAX_CERT_STR_LEN` includes the suffix, `@`, and the shortest
        // possible domain name.
        let name = "a".repeat(MAX_CERT_STR_LEN - CERT_STR_SUFFIX.len() - 1 - 1);
        let valid = cert_id(&name, "d");
        assert_eq!(valid.len(), MAX_CERT_STR_LEN);
        assert!(AlgorithmName::from_certificate_type(&valid).is_ok());

        let too_long_name = "a".repeat(name.len() + 1);
        let too_long = cert_id(&too_long_name, "d");
        assert_eq!(too_long.len(), MAX_CERT_STR_LEN + 1);
        assert!(AlgorithmName::from_certificate_type(&too_long).is_err());
    }
}
