//! Parser for `AuthorizedKeysFile`-formatted data.

use crate::{Error, PublicKey, Result};
use core::{
    fmt::{self, Debug},
    str,
};

#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};

#[cfg(feature = "std")]
use {
    alloc::vec::Vec,
    std::{fs, path::Path},
};

/// Character that begins a comment line
const COMMENT_DELIMITER: char = '#';

/// Maximum length of a single `authorized_keys` line.
///
/// This bounds the work done by the multi-pass parser and prevents a single
/// malicious line from causing CPU amplification.
const MAX_AUTHORIZED_KEYS_LINE_LEN: usize = 64 * 1024;

/// Maximum length of the options field.
const MAX_OPTIONS_LEN: usize = 64 * 1024;

/// Maximum number of comma-delimited options.
const MAX_OPTIONS_COUNT: usize = 1024;

/// Parser for `AuthorizedKeysFile`-formatted data, typically found in
/// `~/.ssh/authorized_keys`.
///
/// For a full description of the format, see:
/// <https://man7.org/linux/man-pages/man8/sshd.8.html#AUTHORIZED_KEYS_FILE_FORMAT>
///
/// Each line of the file consists of a single public key. Blank lines are ignored.
///
/// Public keys consist of the following space-separated fields:
///
/// ```text
/// options, keytype, base64-encoded key, comment
/// ```
///
/// - The options field is optional.
/// - The keytype is `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`,
///   `ssh-ed25519`, `ssh-dss` or `ssh-rsa`
/// - The comment field is not used for anything (but may be convenient for the user to identify
///   the key).
pub struct AuthorizedKeys<'a> {
    /// Lines of the file being iterated over
    lines: str::Lines<'a>,
}

impl<'a> AuthorizedKeys<'a> {
    /// Create a new parser for the given input buffer.
    #[must_use]
    pub fn new(input: &'a str) -> Self {
        Self {
            lines: input.lines(),
        }
    }

    /// Read an [`AuthorizedKeys`] file from the filesystem, returning an [`Entry`] vector on
    /// success.
    ///
    /// # Errors
    /// - Returns [`Error::Io`] in event of I/O errors reading the file.
    /// - Propagates [`Entry`] parsing errors as [`Error::FormatEncoding`].
    #[cfg(feature = "std")]
    pub fn read_file(path: impl AsRef<Path>) -> Result<Vec<Entry>> {
        // TODO(tarcieri): permissions checks
        let input = fs::read_to_string(path)?;
        AuthorizedKeys::new(&input).collect()
    }

    /// Get the next line, skipping comment lines and trailing whitespace. Ignores empty lines.
    fn next_line_trimmed(&mut self) -> Option<&'a str> {
        loop {
            let line = self.lines.next()?;

            // OpenSSH treats a line as a comment only when its first
            // non-whitespace character is `#`. A `#` elsewhere is part of the
            // key comment and must not be stripped.
            if is_comment_line(line) {
                continue;
            }

            let line = line.trim_end();

            if !line.is_empty() {
                return Some(line);
            }
        }
    }
}

impl Debug for AuthorizedKeys<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizedKeys").finish_non_exhaustive()
    }
}

impl Iterator for AuthorizedKeys<'_> {
    type Item = Result<Entry>;

    fn next(&mut self) -> Option<Result<Entry>> {
        self.next_line_trimmed().map(str::parse)
    }
}

/// Individual entry in an `authorized_keys` file containing a single public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    /// Configuration options field, if present.
    #[cfg(feature = "alloc")]
    config_opts: ConfigOpts,

    /// Public key
    public_key: PublicKey,
}

impl Entry {
    /// Get configuration options for this entry.
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn config_opts(&self) -> &ConfigOpts {
        &self.config_opts
    }

    /// Get public key for this entry.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

#[cfg(feature = "alloc")]
impl From<Entry> for ConfigOpts {
    fn from(entry: Entry) -> ConfigOpts {
        entry.config_opts
    }
}

impl From<Entry> for PublicKey {
    fn from(entry: Entry) -> PublicKey {
        entry.public_key
    }
}

impl From<PublicKey> for Entry {
    fn from(public_key: PublicKey) -> Entry {
        Entry {
            #[cfg(feature = "alloc")]
            config_opts: ConfigOpts::default(),
            public_key,
        }
    }
}

impl str::FromStr for Entry {
    type Err = Error;

    fn from_str(line: &str) -> Result<Self> {
        // `Entry` is also public as a `FromStr` implementation, so it must not
        // accept an `authorized_keys` comment line as an options entry.
        if is_comment_line(line) {
            return Err(Error::FormatEncoding);
        }

        if line.len() > MAX_AUTHORIZED_KEYS_LINE_LEN {
            return Err(Error::FormatEncoding);
        }

        // Fast path: the whole line is a key, optionally followed by a comment
        // which may itself contain spaces.
        if let Ok(public_key) = line.parse() {
            return Ok(Self {
                #[cfg(feature = "alloc")]
                config_opts: Default::default(),
                public_key,
            });
        }

        // A key without options may use tabs (or repeated whitespace) between
        // its fields. Try that before treating the first field as options.
        if let Ok(public_key) = parse_public_key_fields(line) {
            return Ok(Self {
                #[cfg(feature = "alloc")]
                config_opts: Default::default(),
                public_key,
            });
        }

        // Otherwise the first field is an options list followed by the key.
        let (config_opts_str, public_key_str) =
            split_options_and_key(line).ok_or(Error::FormatEncoding)?;

        ConfigOptsIter(config_opts_str).validate()?;
        let public_key = parse_public_key_fields(public_key_str)?;

        Ok(Self {
            #[cfg(feature = "alloc")]
            config_opts: ConfigOpts(config_opts_str.to_string()),
            public_key,
        })
    }
}

/// Does this line begin with a `#` comment marker (after optional whitespace)?
fn is_comment_line(line: &str) -> bool {
    line.trim_start_matches([' ', '\t'])
        .starts_with(COMMENT_DELIMITER)
}

/// Is the byte at `index` the start of an escaped quote (`\"`)?
///
/// OpenSSH's option parser only treats `\"` specially; a backslash before any
/// other character is an ordinary character.
fn is_escaped_quote(bytes: &[u8], index: usize) -> bool {
    bytes.get(index) == Some(&b'\\')
        && index.checked_add(1).and_then(|next| bytes.get(next)) == Some(&b'"')
}

/// Split an optional options field from the following public key.
///
/// The options field may contain quoted values with spaces, so the separator
/// is the first whitespace character outside of double quotes. The scan is a
/// single left-to-right pass; `MAX_OPTIONS_LEN` bounds the options field.
fn split_options_and_key(line: &str) -> Option<(&str, &str)> {
    let line = line.trim_start_matches([' ', '\t']);
    let bytes = line.as_bytes();
    let mut quoted = false;
    let mut index = 0;

    while let Some(&byte) = bytes.get(index) {
        if is_escaped_quote(bytes, index) {
            index = index.checked_add(2)?;
            continue;
        }

        match byte {
            b'"' => quoted = !quoted,
            b' ' | b'\t' if !quoted => {
                let config_opts = &line[..index];
                let public_key = line[index..].trim_start_matches([' ', '\t']);

                if config_opts.is_empty() || public_key.is_empty() {
                    return None;
                }

                return Some((config_opts, public_key));
            }
            _ => (),
        }

        index = index.checked_add(1)?;
    }

    None
}

/// Parse a public key which may use spaces or tabs as field separators.
fn parse_public_key_fields(line: &str) -> Result<PublicKey> {
    #[cfg(feature = "alloc")]
    if let Some(normalized) = normalize_public_key_fields(line) {
        return normalized.parse();
    }

    line.parse()
}

/// Normalize whitespace-separated public key fields to the single-space form
/// expected by [`PublicKey`]'s parser.
#[cfg(feature = "alloc")]
fn normalize_public_key_fields(line: &str) -> Option<String> {
    let line = line.trim_start_matches([' ', '\t']);
    let (algorithm_id, rest) = split_whitespace_once(line)?;
    let (base64_data, comment) = split_whitespace_once(rest).unwrap_or((rest, ""));

    if base64_data.is_empty() {
        return None;
    }

    if comment.is_empty() {
        Some(format!("{algorithm_id} {base64_data}"))
    } else {
        Some(format!("{algorithm_id} {base64_data} {comment}"))
    }
}

/// Split a string at the first space or tab, returning the field and the
/// trimmed remainder.
#[cfg(feature = "alloc")]
fn split_whitespace_once(line: &str) -> Option<(&str, &str)> {
    let index = line.find([' ', '\t'])?;
    let (field, rest) = line.split_at(index);
    let rest = rest.trim_start_matches([' ', '\t']);

    if field.is_empty() || rest.is_empty() {
        return None;
    }

    Some((field, rest))
}

#[cfg(feature = "alloc")]
#[allow(clippy::to_string_trait_impl)]
impl ToString for Entry {
    fn to_string(&self) -> String {
        let mut s = String::new();

        if !self.config_opts.is_empty() {
            s.push_str(self.config_opts.as_str());
            s.push(' ');
        }

        s.push_str(&self.public_key.to_string());
        s
    }
}

/// Configuration options associated with a particular public key.
///
/// These options are a comma-separated list preceding each public key
/// in the `authorized_keys` file.
///
/// The [`ConfigOpts::iter`] method can be used to iterate over each
/// comma-separated value.
#[cfg(feature = "alloc")]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ConfigOpts(String);

#[cfg(feature = "alloc")]
impl ConfigOpts {
    /// Parse an options string.
    ///
    /// # Errors
    ///
    pub fn new(string: impl Into<String>) -> Result<Self> {
        let ret = Self(string.into());
        ret.iter().validate()?;
        Ok(ret)
    }

    /// Borrow the configuration options as a `str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Are there no configuration options?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate over the comma-delimited configuration options.
    #[must_use]
    pub fn iter(&self) -> ConfigOptsIter<'_> {
        ConfigOptsIter(self.as_str())
    }
}

#[cfg(feature = "alloc")]
impl AsRef<str> for ConfigOpts {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[cfg(feature = "alloc")]
impl str::FromStr for ConfigOpts {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

#[cfg(feature = "alloc")]
impl fmt::Display for ConfigOpts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Iterator over configuration options.
#[derive(Clone, Debug)]
pub struct ConfigOptsIter<'a>(&'a str);

impl<'a> ConfigOptsIter<'a> {
    /// Create new configuration options iterator.
    ///
    /// Validates that the options are well-formed.
    ///
    /// # Errors
    /// Returns [`Error::Encoding`] in the event of encoding errors.
    pub fn new(s: &'a str) -> Result<Self> {
        let ret = Self(s);
        ret.clone().validate()?;
        Ok(ret)
    }

    /// Validate that config options are well-formed.
    fn validate(&mut self) -> Result<()> {
        if self.0.len() > MAX_OPTIONS_LEN {
            return Err(encoding::Error::Length.into());
        }

        let mut option_count = 0usize;

        while self.try_next()?.is_some() {
            option_count = option_count.checked_add(1).ok_or(encoding::Error::Length)?;

            if option_count > MAX_OPTIONS_COUNT {
                return Err(encoding::Error::Length.into());
            }
        }

        Ok(())
    }

    /// Attempt to parse the next comma-delimited option string.
    fn try_next(&mut self) -> Result<Option<&'a str>> {
        if self.0.is_empty() {
            return Ok(None);
        }

        let mut quoted = false;
        let mut index = 0;

        while let Some(byte) = self.0.as_bytes().get(index).cloned() {
            if is_escaped_quote(self.0.as_bytes(), index) {
                index = index.checked_add(2).ok_or(encoding::Error::Length)?;
                continue;
            }

            if quoted {
                match byte {
                    b'"' => quoted = false,
                    // A real tab is allowed inside quoted option values.
                    b'\t' | 0x20..=0x7e => (),
                    _ => return Err(encoding::Error::CharacterEncoding.into()),
                }
            } else {
                match byte {
                    b',' => {
                        let (next, rest) = self.0.split_at(index);
                        self.0 = &rest[1..]; // Strip comma
                        return Ok(Some(next));
                    }
                    b'"' => quoted = true,
                    // Valid unquoted characters
                    b'A'..=b'Z'
                    | b'a'..=b'z'
                    | b'0'..=b'9'
                    | b'!'..=b'/'
                    | b':'..=b'@'
                    | b'['..=b'_'
                    | b'{'
                    | b'}'
                    | b'|'
                    | b'~' => (),
                    _ => return Err(encoding::Error::CharacterEncoding.into()),
                }
            }

            index = index.checked_add(1).ok_or(encoding::Error::Length)?;
        }

        if quoted {
            // Unterminated quoted option value.
            return Err(encoding::Error::CharacterEncoding.into());
        }

        let remaining = self.0;
        self.0 = "";
        Ok(Some(remaining))
    }
}

impl<'a> Iterator for ConfigOptsIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        // Ensured valid by constructor
        self.try_next().expect("malformed options string")
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::{
        AuthorizedKeys, ConfigOptsIter, Entry, MAX_AUTHORIZED_KEYS_LINE_LEN, MAX_OPTIONS_COUNT,
        MAX_OPTIONS_LEN,
    };
    use crate::Algorithm;
    use alloc::string::String;
    use alloc::vec::Vec;

    const KEY_DATA: &str = "AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti";

    fn key_line(prefix: &str) -> String {
        format!("{prefix}ssh-ed25519 {KEY_DATA}")
    }

    fn key_line_with_comment(prefix: &str) -> String {
        format!("{} user@example.com", key_line(prefix))
    }

    #[test]
    fn entry_options_without_comment() {
        let entry: Entry = key_line("no-pty ").parse().unwrap();

        assert_eq!(entry.config_opts().as_str(), "no-pty");
        assert_eq!(entry.public_key().algorithm(), Algorithm::Ed25519);
        assert_eq!(entry.public_key().comment().as_str_lossy(), "");
        assert_eq!(
            entry.public_key().to_openssh().unwrap(),
            format!("ssh-ed25519 {KEY_DATA}")
        );
    }

    #[test]
    fn entry_options_with_comment() {
        let entry: Entry = key_line_with_comment("no-pty ").parse().unwrap();

        assert_eq!(entry.config_opts().as_str(), "no-pty");
        assert_eq!(
            entry.public_key().comment().as_str_lossy(),
            "user@example.com"
        );
    }

    #[test]
    fn entry_key_without_options() {
        let without_comment: Entry = key_line("").parse().unwrap();
        assert!(without_comment.config_opts().is_empty());
        assert_eq!(without_comment.public_key().comment().as_str_lossy(), "");

        let with_comment: Entry = key_line_with_comment("").parse().unwrap();
        assert!(with_comment.config_opts().is_empty());
        assert_eq!(
            with_comment.public_key().comment().as_str_lossy(),
            "user@example.com"
        );
    }

    #[test]
    fn entry_tab_separated_fields() {
        let entry: Entry = format!("no-pty\tssh-ed25519\t{KEY_DATA}").parse().unwrap();
        assert_eq!(entry.config_opts().as_str(), "no-pty");
        assert_eq!(entry.public_key().algorithm(), Algorithm::Ed25519);

        let entry: Entry = format!("ssh-ed25519\t{KEY_DATA}\tuser@example.com")
            .parse()
            .unwrap();
        assert!(entry.config_opts().is_empty());
        assert_eq!(
            entry.public_key().comment().as_str_lossy(),
            "user@example.com"
        );
    }

    #[test]
    fn entry_quoted_options() {
        let line = key_line(r#"command="echo hello, world",no-pty "#);
        let entry: Entry = line.parse().unwrap();
        assert_eq!(
            entry.config_opts().as_str(),
            r#"command="echo hello, world",no-pty"#
        );

        // A `#` (and spaces) inside a quoted value is data, not a comment.
        let line = key_line(r#"command="echo # not a comment" "#);
        let entry: Entry = line.parse().unwrap();
        assert_eq!(
            entry.config_opts().as_str(),
            r#"command="echo # not a comment""#
        );

        // Escaped quotes do not terminate the quoted value.
        let line = key_line(r#"command="echo \"hello\"",no-pty "#);
        let entry: Entry = line.parse().unwrap();
        assert_eq!(
            entry.config_opts().as_str(),
            r#"command="echo \"hello\"",no-pty"#
        );

        // A real tab is valid inside a quoted option value.
        let line = key_line("command=\"echo\thi\" ");
        let entry: Entry = line.parse().unwrap();
        assert_eq!(entry.config_opts().as_str(), "command=\"echo\thi\"");

        // Backslash before a non-quote is an ordinary character.
        let line = key_line(r#"command="C:\path" "#);
        let entry: Entry = line.parse().unwrap();
        assert_eq!(entry.config_opts().as_str(), r#"command="C:\path""#);

        // `\"` is treated consistently outside quotes too: it does not open
        // a new quoted section.
        let line = key_line(r#"command=echo\"hi "#);
        let entry: Entry = line.parse().unwrap();
        assert_eq!(entry.config_opts().as_str(), r#"command=echo\"hi"#);
    }

    #[test]
    fn entry_comment_may_contain_hash() {
        let entry: Entry = format!("ssh-ed25519 {KEY_DATA} user#name").parse().unwrap();
        assert_eq!(entry.public_key().comment().as_str_lossy(), "user#name");

        let entry: Entry = format!("no-pty ssh-ed25519 {KEY_DATA} user#name")
            .parse()
            .unwrap();
        assert_eq!(entry.config_opts().as_str(), "no-pty");
        assert_eq!(entry.public_key().comment().as_str_lossy(), "user#name");
    }

    #[test]
    fn entry_rejects_inline_hash_after_base64() {
        // A `#` is not a comment marker here; it makes the base64 field
        // invalid instead of silently truncating the key.
        assert!(
            format!("ssh-ed25519 {KEY_DATA}#junk")
                .parse::<Entry>()
                .is_err()
        );
        assert!(
            format!("no-pty ssh-ed25519 {KEY_DATA}#junk")
                .parse::<Entry>()
                .is_err()
        );
    }

    #[test]
    fn entry_rejects_comment_line() {
        assert!(
            format!("# ssh-ed25519 {KEY_DATA}")
                .parse::<Entry>()
                .is_err()
        );
        assert!(
            format!("  # ssh-ed25519 {KEY_DATA}")
                .parse::<Entry>()
                .is_err()
        );
        assert!(
            format!("\t# ssh-ed25519 {KEY_DATA}")
                .parse::<Entry>()
                .is_err()
        );
    }

    #[test]
    fn entry_rejects_invalid_lines() {
        // Invalid base64 key data.
        assert!(
            key_line("no-pty ")
                .replace(KEY_DATA, "not-base64")
                .parse::<Entry>()
                .is_err()
        );

        // Unquoted whitespace inside the options field.
        assert!(key_line("no-pty extra ").parse::<Entry>().is_err());

        // Unterminated quoted option.
        assert!(
            key_line("command=\"unterminated ")
                .parse::<Entry>()
                .is_err()
        );

        // Key type only.
        assert!("no-pty".parse::<Entry>().is_err());
    }

    #[test]
    fn entry_rejects_oversized_input() {
        let line = format!(
            "ssh-ed25519 {KEY_DATA} {}",
            "a".repeat(MAX_AUTHORIZED_KEYS_LINE_LEN)
        );
        assert!(line.parse::<Entry>().is_err());

        let opts = format!("{}no-pty", "no-pty,".repeat(MAX_OPTIONS_COUNT));
        let line = format!("{opts} ssh-ed25519 {KEY_DATA}");
        assert!(line.parse::<Entry>().is_err());
    }

    #[test]
    fn options_length_limit() {
        let opts = "a".repeat(MAX_OPTIONS_LEN + 1);
        assert!(ConfigOptsIter::new(&opts).is_err());
    }

    #[test]
    fn authorized_keys_ignores_blank_and_comment_lines() {
        let input = format!(
            "# heading\n\n   # indented heading\n\t# tab heading\nno-pty ssh-ed25519 {KEY_DATA}\nssh-ed25519 {KEY_DATA} user#name\n"
        );
        let entries = AuthorizedKeys::new(&input)
            .collect::<crate::Result<Vec<_>>>()
            .unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].config_opts().as_str(), "no-pty");
        assert!(entries[1].config_opts().is_empty());
        assert_eq!(
            entries[1].public_key().comment().as_str_lossy(),
            "user#name"
        );
    }

    #[test]
    fn options_empty() {
        assert_eq!(ConfigOptsIter("").try_next(), Ok(None));
    }

    #[test]
    fn options_no_comma() {
        let mut opts = ConfigOptsIter("foo");
        assert_eq!(opts.try_next(), Ok(Some("foo")));
        assert_eq!(opts.try_next(), Ok(None));
    }

    #[test]
    fn options_no_comma_quoted() {
        let mut opts = ConfigOptsIter("foo=\"bar\"");
        assert_eq!(opts.try_next(), Ok(Some("foo=\"bar\"")));
        assert_eq!(opts.try_next(), Ok(None));

        // Comma inside quoted section
        let mut opts = ConfigOptsIter("foo=\"bar,baz\"");
        assert_eq!(opts.try_next(), Ok(Some("foo=\"bar,baz\"")));
        assert_eq!(opts.try_next(), Ok(None));
    }

    #[test]
    fn options_quoted_space_and_escape() {
        let mut opts = ConfigOptsIter(r#"command="echo hi, there",no-pty"#);
        assert_eq!(opts.try_next(), Ok(Some(r#"command="echo hi, there""#)));
        assert_eq!(opts.try_next(), Ok(Some("no-pty")));
        assert_eq!(opts.try_next(), Ok(None));

        let mut opts = ConfigOptsIter(r#"command="echo \"hi\"""#);
        assert_eq!(opts.try_next(), Ok(Some(r#"command="echo \"hi\"""#)));
        assert_eq!(opts.try_next(), Ok(None));

        // Real tab inside quotes.
        let mut opts = ConfigOptsIter("command=\"echo\thi\"");
        assert_eq!(opts.try_next(), Ok(Some("command=\"echo\thi\"")));
        assert_eq!(opts.try_next(), Ok(None));

        // Backslash only escapes `"`; before other characters it is literal.
        let mut opts = ConfigOptsIter(r#"command="C:\path""#);
        assert_eq!(opts.try_next(), Ok(Some(r#"command="C:\path""#)));
        assert_eq!(opts.try_next(), Ok(None));

        // `\"` outside quotes is escaped consistently and does not open a
        // quoted section.
        let mut opts = ConfigOptsIter(r#"command=echo\"hi"#);
        assert_eq!(opts.try_next(), Ok(Some(r#"command=echo\"hi"#)));
        assert_eq!(opts.try_next(), Ok(None));
    }

    #[test]
    fn options_unterminated_quote_is_error() {
        let mut opts = ConfigOptsIter("command=\"unterminated");
        assert!(opts.try_next().is_err());

        // The quote is escaped, so the value is still unterminated.
        let mut opts = ConfigOptsIter(r#"command="unterminated\""#);
        assert!(opts.try_next().is_err());
    }

    #[test]
    fn options_control_character_inside_quotes_is_error() {
        let mut opts = ConfigOptsIter("command=\"echo\x01\"");
        assert!(opts.try_next().is_err());
    }

    #[test]
    fn options_comma_delimited() {
        let mut opts = ConfigOptsIter("foo,bar");
        assert_eq!(opts.try_next(), Ok(Some("foo")));
        assert_eq!(opts.try_next(), Ok(Some("bar")));
        assert_eq!(opts.try_next(), Ok(None));
    }

    #[test]
    fn options_comma_delimited_quoted() {
        let mut opts = ConfigOptsIter("foo=\"bar\",baz");
        assert_eq!(opts.try_next(), Ok(Some("foo=\"bar\"")));
        assert_eq!(opts.try_next(), Ok(Some("baz")));
        assert_eq!(opts.try_next(), Ok(None));
    }

    #[test]
    fn options_invalid_character() {
        let mut opts = ConfigOptsIter("❌");
        assert_eq!(
            opts.try_next(),
            Err(encoding::Error::CharacterEncoding.into())
        );

        let mut opts = ConfigOptsIter("x,❌");
        assert_eq!(opts.try_next(), Ok(Some("x")));
        assert_eq!(
            opts.try_next(),
            Err(encoding::Error::CharacterEncoding.into())
        );
    }
}
