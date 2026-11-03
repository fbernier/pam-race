//! Domain types. Every value crossing a boundary (module arguments, the
//! helper socket, the PAM conversation) is parsed into one of these once;
//! past that point invariants hold by construction.

use std::ffi::{CStr, CString, c_int};
use std::fmt;
use std::num::NonZeroI32;

use crate::ffi;

// ------------------------------------------------------------------ results

/// A PAM return code other than PAM_SUCCESS.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PamError(NonZeroI32);

pub type PamResult = Result<(), PamError>;

impl PamError {
    pub const SERVICE_ERR: PamError = PamError::known(ffi::PAM_SERVICE_ERR);
    pub const SYSTEM_ERR: PamError = PamError::known(ffi::PAM_SYSTEM_ERR);
    pub const BUF_ERR: PamError = PamError::known(ffi::PAM_BUF_ERR);
    pub const AUTH_ERR: PamError = PamError::known(ffi::PAM_AUTH_ERR);
    pub const CONV_ERR: PamError = PamError::known(ffi::PAM_CONV_ERR);

    const fn known(code: c_int) -> PamError {
        match NonZeroI32::new(code) {
            Some(c) => PamError(c),
            None => panic!("PAM_SUCCESS is not an error"),
        }
    }

    pub fn code(self) -> c_int {
        self.0.get()
    }
}

/// Parse a raw PAM return code.
pub fn pam_result(code: c_int) -> PamResult {
    NonZeroI32::new(code).map_or(Ok(()), |c| Err(PamError(c)))
}

/// Back to a raw PAM return code.
pub fn pam_code(r: PamResult) -> c_int {
    r.map_or_else(PamError::code, |()| ffi::PAM_SUCCESS)
}

impl fmt::Display for PamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PAM error {}", self.0)
    }
}

// --------------------------------------------------------------- messages

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Style {
    PromptEchoOff,
    PromptEchoOn,
    ErrorMsg,
    TextInfo,
}

impl Style {
    /// `None` for styles this module does not carry (e.g. binary prompts).
    pub fn parse(raw: c_int) -> Option<Style> {
        Some(match raw {
            ffi::PAM_PROMPT_ECHO_OFF => Style::PromptEchoOff,
            ffi::PAM_PROMPT_ECHO_ON => Style::PromptEchoOn,
            ffi::PAM_ERROR_MSG => Style::ErrorMsg,
            ffi::PAM_TEXT_INFO => Style::TextInfo,
            _ => return None,
        })
    }

    pub fn raw(self) -> c_int {
        match self {
            Style::PromptEchoOff => ffi::PAM_PROMPT_ECHO_OFF,
            Style::PromptEchoOn => ffi::PAM_PROMPT_ECHO_ON,
            Style::ErrorMsg => ffi::PAM_ERROR_MSG,
            Style::TextInfo => ffi::PAM_TEXT_INFO,
        }
    }

    pub fn is_prompt(self) -> bool {
        matches!(self, Style::PromptEchoOff | Style::PromptEchoOn)
    }
}

/// Message text: no NUL, at most [`Text::MAX`] bytes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Text(CString);

impl Text {
    /// PAM_MAX_MSG_SIZE is 512, but modules are not bound by it.
    pub const MAX: usize = 4096;

    pub fn parse(b: &[u8]) -> Option<Text> {
        if b.len() > Text::MAX {
            return None;
        }
        CString::new(b).ok().map(Text)
    }

    /// Text from a module, cut to [`Text::MAX`] bytes. The cut backs up to
    /// the start of a UTF-8 sequence rather than splitting a character; other
    /// encodings lose at most three more bytes.
    pub fn truncating(s: &CStr) -> Text {
        let b = s.to_bytes();
        let mut end = b.len().min(Text::MAX);
        if end < b.len() {
            let lead = b[..end]
                .iter()
                .rev()
                .take(4)
                .position(|&c| c & 0b1100_0000 != 0b1000_0000);
            if let Some(back) = lead {
                let start = end - back - 1;
                if start + utf8_len(b[start]) > end {
                    end = start;
                }
            }
        }
        Text(CString::new(&b[..end]).expect("CStr has no interior NUL"))
    }

    pub fn as_cstr(&self) -> &CStr {
        &self.0
    }
}

/// Length of the UTF-8 sequence a lead byte announces (1 for anything else).
fn utf8_len(lead: u8) -> usize {
    match lead {
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => 1,
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Message {
    pub style: Style,
    pub text: Text,
}

/// The messages of one conversation call: 1..=PAM_MAX_NUM_MSG of them.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Messages(Vec<Message>);

impl Messages {
    pub fn parse(v: Vec<Message>) -> Option<Messages> {
        (1..=ffi::PAM_MAX_NUM_MSG)
            .contains(&v.len())
            .then_some(Messages(v))
    }

    pub fn as_slice(&self) -> &[Message] {
        &self.0
    }

    #[expect(clippy::len_without_is_empty, reason = "never empty by construction")]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the call waits for user input.
    pub fn is_prompt(&self) -> bool {
        self.0.iter().any(|m| m.style.is_prompt())
    }
}

/// Heap bytes wiped on drop: holds passwords on both sides of the socket.
#[derive(Default)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(v: Vec<u8>) -> Self {
        Self(v)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // The whole allocation, not just len.
        let cap = self.0.capacity();
        if cap != 0 {
            unsafe { libc::explicit_bzero(self.0.as_mut_ptr().cast(), cap) };
        }
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// Answers to one conversation call: exactly one slot per message, each at
/// most [`Responses::MAX_ANSWER`] bytes, so a reply always fits one packet.
#[derive(Debug)]
pub struct Responses(Vec<Option<Secret>>);

impl Responses {
    pub const MAX_ANSWER: usize = Text::MAX;

    pub fn parse(v: Vec<Option<Secret>>, to: &Messages) -> Option<Responses> {
        let ok = v.len() == to.len()
            && v.iter()
                .flatten()
                .all(|s| s.as_bytes().len() <= Responses::MAX_ANSWER);
        ok.then_some(Responses(v))
    }

    pub fn as_slice(&self) -> &[Option<Secret>] {
        &self.0
    }
}

// ------------------------------------------------------------ identifiers

/// A PAM service name: a plain file name inside the PAM config directory.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ServiceName(CString);

impl ServiceName {
    pub fn parse(s: &[u8]) -> Option<ServiceName> {
        let ok = !s.is_empty()
            && s.len() <= 255
            && s[0] != b'.'
            && s.iter()
                .all(|&b| b.is_ascii_alphanumeric() || b"._+-".contains(&b));
        ok.then(|| ServiceName(CString::new(s).expect("charset excludes NUL")))
    }

    pub fn as_cstr(&self) -> &CStr {
        &self.0
    }
}

impl fmt::Display for ServiceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_string_lossy())
    }
}

/// An absolute filesystem path.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AbsPath(CString);

impl AbsPath {
    pub fn parse(b: &[u8]) -> Option<AbsPath> {
        if b.first() != Some(&b'/') {
            return None;
        }
        CString::new(b).ok().map(AbsPath)
    }

    pub fn as_cstr(&self) -> &CStr {
        &self.0
    }
}

impl fmt::Display for AbsPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_string_lossy())
    }
}

/// A non-empty user name.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UserName(CString);

impl UserName {
    pub fn parse(b: &[u8]) -> Option<UserName> {
        if b.is_empty() {
            return None;
        }
        CString::new(b).ok().map(UserName)
    }

    pub fn as_cstr(&self) -> &CStr {
        &self.0
    }
}

impl fmt::Display for UserName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_string_lossy())
    }
}

/// The value of a string PAM item forwarded to the sub-stacks (`PAM_TTY`,
/// `PAM_RHOST`, `PAM_RUSER`): no NUL, at most [`ItemValue::MAX`] bytes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ItemValue(CString);

impl ItemValue {
    pub const MAX: usize = 4096;

    pub fn parse(b: &[u8]) -> Option<ItemValue> {
        if b.len() > ItemValue::MAX {
            return None;
        }
        CString::new(b).ok().map(ItemValue)
    }

    pub fn as_cstr(&self) -> &CStr {
        &self.0
    }
}

/// Flags forwarded to `pam_authenticate` in the sub-stack.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AuthFlags(c_int);

impl AuthFlags {
    const ALLOWED: c_int = ffi::PAM_SILENT | ffi::PAM_DISALLOW_NULL_AUTHTOK;

    /// Keeps only the flags meaningful to `pam_authenticate`.
    pub fn from_raw(raw: c_int) -> AuthFlags {
        AuthFlags(raw & AuthFlags::ALLOWED)
    }

    pub fn raw(self) -> c_int {
        self.0
    }
}

/// Index of a helper, in configuration order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HelperId(pub usize);

// ----------------------------------------------------------------- terminal

/// The controlling terminal as seen when deciding whether to push a newline
/// into it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TtyState {
    /// The host is not in the terminal's foreground process group, so it is
    /// not the one reading it (and a shell may be). Also: state unknown.
    Background,
    /// A complete line is already waiting for the reader.
    LineQueued,
    /// The host is in the foreground and no complete line is queued.
    Idle,
}

// -------------------------------------------------------------- environment

/// The locale variables the helper inherits, so modules speak the user's
/// language.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LocaleVar {
    Lang,
    Language,
    LcAll,
    LcMessages,
    LcCtype,
}

impl LocaleVar {
    pub const ALL: [LocaleVar; 5] = [
        LocaleVar::Lang,
        LocaleVar::Language,
        LocaleVar::LcAll,
        LocaleVar::LcMessages,
        LocaleVar::LcCtype,
    ];

    pub fn name(self) -> &'static str {
        match self {
            LocaleVar::Lang => "LANG",
            LocaleVar::Language => "LANGUAGE",
            LocaleVar::LcAll => "LC_ALL",
            LocaleVar::LcMessages => "LC_MESSAGES",
            LocaleVar::LcCtype => "LC_CTYPE",
        }
    }
}

/// A `NAME=value` environment entry for a [`LocaleVar`] whose value is a
/// locale name (`LANGUAGE`: a `:`-separated list of them) and nothing else.
///
/// The value comes from the user, while the helper may run as root without
/// AT_SECURE (host already did `setuid(0)`): no `/` (glibc accepts locale
/// paths), no leading `.` (no `..` component), no control or non-ASCII bytes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LocaleEnv(CString);

impl LocaleEnv {
    const MAX: usize = 255;

    pub fn parse(var: LocaleVar, value: &[u8]) -> Option<LocaleEnv> {
        let name_ok = |n: &[u8]| {
            n.first().is_some_and(|&b| b != b'.')
                && n.iter()
                    .all(|&b| b.is_ascii_alphanumeric() || b"_.@+-".contains(&b))
        };
        let ok = value.len() <= LocaleEnv::MAX
            && match var {
                LocaleVar::Language => value.split(|&b| b == b':').all(name_ok),
                _ => name_ok(value),
            };
        ok.then(|| {
            let mut kv = Vec::from(var.name().as_bytes());
            kv.push(b'=');
            kv.extend_from_slice(value);
            LocaleEnv(CString::new(kv).expect("charset excludes NUL"))
        })
    }

    pub fn as_cstr(&self) -> &CStr {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_never_splits_a_utf8_character() {
        for prefix in 0..4 {
            // "é" (2 bytes), "€" (3), "𝄞" (4) straddling the limit.
            for ch in ["é", "€", "𝄞"] {
                let s = "a".repeat(Text::MAX - prefix) + &ch.repeat(4);
                let t = Text::truncating(&CString::new(s).unwrap());
                let b = t.as_cstr().to_bytes();
                assert!(b.len() <= Text::MAX);
                assert!(b.len() > Text::MAX - 4, "cut at most one character");
                assert!(std::str::from_utf8(b).is_ok(), "{prefix} {ch}");
            }
        }
        let exact = "a".repeat(Text::MAX - 2) + "é";
        let t = Text::truncating(&CString::new(exact.clone()).unwrap());
        assert_eq!(t.as_cstr().to_bytes(), exact.as_bytes(), "fits: untouched");
        let latin1 = vec![0xe9u8; Text::MAX + 10];
        let t = Text::truncating(&CString::new(latin1).unwrap());
        let n = t.as_cstr().to_bytes().len();
        assert!(
            (Text::MAX - 3..=Text::MAX).contains(&n),
            "not UTF-8: about the limit"
        );
    }

    #[test]
    fn locale_values_are_names_not_paths() {
        let ok = |v: LocaleVar, s: &str| {
            LocaleEnv::parse(v, s.as_bytes()).map(|e| e.as_cstr().to_str().unwrap().to_owned())
        };
        assert_eq!(
            ok(LocaleVar::Lang, "fr_FR.UTF-8").as_deref(),
            Some("LANG=fr_FR.UTF-8")
        );
        assert!(ok(LocaleVar::LcMessages, "sr_RS@latin").is_some());
        assert!(ok(LocaleVar::Language, "fr_CA:fr:en").is_some());
        for bad in [
            "",
            "/tmp/evil",
            "..",
            ".hidden",
            "fr\n",
            "fr FR",
            "fr:en",
            "ü",
        ] {
            assert_eq!(ok(LocaleVar::Lang, bad), None, "{bad:?}");
        }
        for bad in ["fr:..", "fr::en", "fr:/tmp", ":fr"] {
            assert_eq!(ok(LocaleVar::Language, bad), None, "{bad:?}");
        }
        assert_eq!(ok(LocaleVar::LcAll, &"a".repeat(256)), None);
    }

    #[test]
    fn answers_longer_than_a_packet_allows_are_rejected() {
        let to = Messages::parse(vec![Message {
            style: Style::PromptEchoOff,
            text: Text::parse(b"Password: ").unwrap(),
        }])
        .unwrap();
        let answer = |n| vec![Some(Secret::new(vec![b'x'; n]))];
        assert!(Responses::parse(answer(Responses::MAX_ANSWER), &to).is_some());
        assert!(Responses::parse(answer(Responses::MAX_ANSWER + 1), &to).is_none());
    }
}
