//! Wire format between the module and `pam-race-helper` (pure; no I/O).
//!
//! Carried over an `AF_UNIX`/`SOCK_SEQPACKET` socketpair, so every packet
//! arrives whole and EOF means the peer is gone. A packet is a one-byte tag
//! then fixed little-endian fields; strings are `u32` length + bytes.
//!
//! ```text
//! module -> helper   Setup  { flags, service, user, tty?, rhost?, ruser?, confdir? }
//! helper -> module   Conv   { [ (style, text) ] }        one pam_conv() call
//! module -> helper   Reply  { [ response? ] }            only for calls that prompt
//! helper -> module   Done   { pam_authenticate() code }
//! ```

use std::ffi::c_int;
use std::fmt;

use crate::ffi::PAM_MAX_NUM_MSG;
use crate::types::*;

/// Upper bound for a packet: 32 messages of `Text::MAX` bytes plus framing.
pub const MAX_PACKET: usize = 192 * 1024;

// The largest reply, every answer of a full call at its limit, fits a packet.
const _: () =
    assert!(2 + crate::ffi::PAM_MAX_NUM_MSG * (1 + 4 + Responses::MAX_ANSWER) <= MAX_PACKET);

const TAG_SETUP: u8 = 1;
const TAG_CONV: u8 = 2;
const TAG_REPLY: u8 = 3;
const TAG_DONE: u8 = 4;

#[derive(Debug, PartialEq, Eq)]
pub struct Setup {
    pub flags: AuthFlags,
    pub service: ServiceName,
    pub user: UserName,
    pub tty: Option<ItemValue>,
    pub rhost: Option<ItemValue>,
    pub ruser: Option<ItemValue>,
    pub confdir: Option<AbsPath>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FromHelper {
    Conv(Messages),
    Done(PamResult),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProtoError {
    Truncated,
    TrailingBytes,
    UnexpectedTag(u8),
    Invalid(&'static str),
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtoError::Truncated => write!(f, "truncated packet"),
            ProtoError::TrailingBytes => write!(f, "trailing bytes in packet"),
            ProtoError::UnexpectedTag(t) => write!(f, "unexpected packet tag {t}"),
            ProtoError::Invalid(what) => write!(f, "invalid {what}"),
        }
    }
}

// ---------------------------------------------------------------- encoding

struct W(Vec<u8>);

impl W {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn i32(&mut self, v: c_int) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.0.extend_from_slice(&(b.len() as u32).to_le_bytes());
        self.0.extend_from_slice(b);
    }
    fn opt(&mut self, b: Option<&[u8]>) {
        match b {
            None => self.u8(0),
            Some(b) => {
                self.u8(1);
                self.bytes(b);
            }
        }
    }
}

pub fn encode_setup(s: &Setup) -> Vec<u8> {
    let mut w = W(vec![TAG_SETUP]);
    w.i32(s.flags.raw());
    w.bytes(s.service.as_cstr().to_bytes());
    w.bytes(s.user.as_cstr().to_bytes());
    for item in [&s.tty, &s.rhost, &s.ruser] {
        w.opt(item.as_ref().map(|v| v.as_cstr().to_bytes()));
    }
    w.opt(s.confdir.as_ref().map(|p| p.as_cstr().to_bytes()));
    w.0
}

pub fn encode_conv(msgs: &Messages) -> Vec<u8> {
    let mut w = W(vec![TAG_CONV]);
    w.u8(msgs.len() as u8);
    for m in msgs.as_slice() {
        w.i32(m.style.raw());
        w.bytes(m.text.as_cstr().to_bytes());
    }
    w.0
}

/// Contains passwords, hence the wiped buffer.
pub fn encode_reply(r: &Responses) -> Secret {
    let len = 2 + r
        .as_slice()
        .iter()
        .map(|x| 1 + x.as_ref().map_or(0, |s| 4 + s.as_bytes().len()))
        .sum::<usize>();
    let mut w = W(Vec::with_capacity(len));
    w.u8(TAG_REPLY);
    w.u8(r.as_slice().len() as u8);
    for x in r.as_slice() {
        w.opt(x.as_ref().map(Secret::as_bytes));
    }
    debug_assert_eq!(
        w.0.len(),
        len,
        "capacity must be exact so nothing is reallocated unwiped"
    );
    Secret::new(w.0)
}

pub fn encode_done(r: PamResult) -> Vec<u8> {
    let mut w = W(vec![TAG_DONE]);
    w.i32(pam_code(r));
    w.0
}

// ---------------------------------------------------------------- decoding

struct R<'a>(&'a [u8]);

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        if self.0.len() < n {
            return Err(ProtoError::Truncated);
        }
        let (h, t) = self.0.split_at(n);
        self.0 = t;
        Ok(h)
    }
    fn u8(&mut self) -> Result<u8, ProtoError> {
        Ok(self.take(1)?[0])
    }
    fn i32(&mut self) -> Result<c_int, ProtoError> {
        Ok(c_int::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn bytes(&mut self) -> Result<&'a [u8], ProtoError> {
        let n = u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize;
        self.take(n)
    }
    fn present(&mut self) -> Result<bool, ProtoError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ProtoError::Invalid("option marker")),
        }
    }
    fn item(&mut self) -> Result<Option<ItemValue>, ProtoError> {
        if !self.present()? {
            return Ok(None);
        }
        ItemValue::parse(self.bytes()?)
            .map(Some)
            .ok_or(ProtoError::Invalid("item"))
    }
    fn count(&mut self) -> Result<usize, ProtoError> {
        let n = self.u8()? as usize;
        if !(1..=PAM_MAX_NUM_MSG).contains(&n) {
            return Err(ProtoError::Invalid("message count"));
        }
        Ok(n)
    }
    fn finish<T>(self, v: T) -> Result<T, ProtoError> {
        if self.0.is_empty() {
            Ok(v)
        } else {
            Err(ProtoError::TrailingBytes)
        }
    }
}

fn tag(r: &mut R<'_>, want: u8) -> Result<(), ProtoError> {
    match r.u8()? {
        t if t == want => Ok(()),
        t => Err(ProtoError::UnexpectedTag(t)),
    }
}

pub fn decode_setup(b: &[u8]) -> Result<Setup, ProtoError> {
    let mut r = R(b);
    tag(&mut r, TAG_SETUP)?;
    let flags = AuthFlags::from_raw(r.i32()?);
    let service = ServiceName::parse(r.bytes()?).ok_or(ProtoError::Invalid("service name"))?;
    let user = UserName::parse(r.bytes()?).ok_or(ProtoError::Invalid("user name"))?;
    let (tty, rhost, ruser) = (r.item()?, r.item()?, r.item()?);
    let confdir = match r.present()? {
        false => None,
        true => Some(AbsPath::parse(r.bytes()?).ok_or(ProtoError::Invalid("confdir"))?),
    };
    r.finish(Setup {
        flags,
        service,
        user,
        tty,
        rhost,
        ruser,
        confdir,
    })
}

pub fn decode_from_helper(b: &[u8]) -> Result<FromHelper, ProtoError> {
    let mut r = R(b);
    let msg = match r.u8()? {
        TAG_CONV => {
            let n = r.count()?;
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                let style = Style::parse(r.i32()?).ok_or(ProtoError::Invalid("message style"))?;
                let text = Text::parse(r.bytes()?).ok_or(ProtoError::Invalid("message text"))?;
                v.push(Message { style, text });
            }
            FromHelper::Conv(Messages::parse(v).expect("count checked"))
        }
        TAG_DONE => FromHelper::Done(pam_result(r.i32()?)),
        t => return Err(ProtoError::UnexpectedTag(t)),
    };
    r.finish(msg)
}

/// A reply is only meaningful against the call it answers.
pub fn decode_reply(b: &[u8], to: &Messages) -> Result<Responses, ProtoError> {
    let mut r = R(b);
    tag(&mut r, TAG_REPLY)?;
    let n = r.count()?;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(match r.present()? {
            false => None,
            true => Some(Secret::new(r.bytes()?.to_vec())),
        });
    }
    let resps = Responses::parse(v, to).ok_or(ProtoError::Invalid("responses"))?;
    r.finish(resps)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msgs(n: usize) -> Messages {
        let m = Message {
            style: Style::PromptEchoOff,
            text: Text::parse(b"Password: ").unwrap(),
        };
        Messages::parse(vec![m; n]).unwrap()
    }

    #[test]
    fn every_truncation_of_a_valid_packet_is_rejected() {
        let pkt = encode_conv(&msgs(2));
        assert_eq!(decode_from_helper(&pkt), Ok(FromHelper::Conv(msgs(2))));
        for len in 0..pkt.len() {
            assert!(
                decode_from_helper(&pkt[..len]).is_err(),
                "accepted {len}-byte prefix"
            );
        }
        let mut long = pkt.clone();
        long.push(0);
        assert_eq!(decode_from_helper(&long), Err(ProtoError::TrailingBytes));
    }

    #[test]
    fn message_count_must_be_within_pam_limits() {
        let mut pkt = encode_conv(&msgs(1));
        pkt[1] = 0;
        assert_eq!(
            decode_from_helper(&pkt[..2]),
            Err(ProtoError::Invalid("message count"))
        );
        pkt[1] = PAM_MAX_NUM_MSG as u8 + 1;
        assert_eq!(
            decode_from_helper(&pkt),
            Err(ProtoError::Invalid("message count"))
        );
    }

    #[test]
    fn embedded_nul_is_rejected() {
        // A NUL would silently truncate the string once handed to C.
        let mut pkt = encode_conv(&msgs(1));
        let at = pkt.windows(4).position(|w| w == b"Pass").unwrap();
        pkt[at + 1] = 0;
        assert_eq!(
            decode_from_helper(&pkt),
            Err(ProtoError::Invalid("message text"))
        );
    }

    #[test]
    fn reply_must_answer_every_message_of_its_call() {
        let two = encode_reply(&Responses::parse(vec![None, None], &msgs(2)).unwrap());
        assert!(decode_reply(two.as_bytes(), &msgs(2)).is_ok());
        assert_eq!(
            decode_reply(two.as_bytes(), &msgs(3)).unwrap_err(),
            ProtoError::Invalid("responses")
        );
    }

    #[test]
    fn reply_preserves_absent_vs_empty_response() {
        let to = msgs(3);
        let v = vec![
            None,
            Some(Secret::new(Vec::new())),
            Some(Secret::new(b"pw".to_vec())),
        ];
        let pkt = encode_reply(&Responses::parse(v, &to).unwrap());
        let r = decode_reply(pkt.as_bytes(), &to).unwrap();
        let got: Vec<_> = r
            .as_slice()
            .iter()
            .map(|x| x.as_ref().map(|s| s.as_bytes().to_vec()))
            .collect();
        assert_eq!(got, vec![None, Some(vec![]), Some(b"pw".to_vec())]);
    }
}
