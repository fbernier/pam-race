//! The controlling terminal, used only to release a host blocked in a prompt.
//!
//! When a method wins while the host application is inside its conversation
//! function reading a password, the host is stuck in `read()` on the terminal
//! and only returns at end of line. Interrupting it with a signal is not an
//! option: sudo, for one, treats an interrupted read as ^C and aborts even if
//! the PAM stack succeeded. Instead a newline is pushed into the terminal's
//! input queue (TIOCSTI), so the host sees an ordinary end of line, returns
//! normally and the (partial) answer is discarded.
//!
//! This is best effort, not a cancellation. The module cannot tell whether
//! the host's prompt reads this terminal at all, and the input queue
//! belongs to the terminal, not to us: any other process reading it may
//! take the newline instead. [`Terminal::state`] narrows that down to what
//! can be observed: the host must be in the terminal's foreground process
//! group (TIOCSTI itself does not check that), and no line may be queued.
//!
//! Since Linux 6.2 with `dev.tty.legacy_tiocsti = 0`, TIOCSTI requires
//! CAP_SYS_ADMIN, which setuid hosts such as sudo, sudo-rs and su have. Other
//! hosts get a written notice asking the user to press Enter instead.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::types::TtyState;

pub struct Terminal {
    fd: OwnedFd,
    /// It takes VT100 cursor control (`TERM` is set and not `dumb`).
    vt: bool,
}

impl Terminal {
    /// The calling process's controlling terminal, if any.
    pub fn open() -> Option<Terminal> {
        let fd = unsafe {
            libc::open(
                c"/dev/tty".as_ptr(),
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        let vt = std::env::var_os("TERM").is_some_and(|t| !t.is_empty() && t != "dumb");
        (fd >= 0).then(|| Terminal {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            vt,
        })
    }

    /// Queue a newline as if typed.
    pub fn push_newline(&self) -> io::Result<()> {
        let c: libc::c_char = b'\n' as _;
        if unsafe { libc::ioctl(self.fd.as_raw_fd(), libc::TIOCSTI, &c) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// What a pushed newline would run into. Any error reads as
    /// [`TtyState::Background`]: nothing is pushed into a terminal we cannot
    /// see.
    pub fn state(&self) -> TtyState {
        let fd = self.fd.as_raw_fd();
        // A background host is not reading; whoever is would take the
        // newline as Enter (a shell running a half-typed command line).
        if unsafe { libc::tcgetpgrp(fd) } != unsafe { libc::getpgrp() } {
            return TtyState::Background;
        }
        // In canonical mode only complete lines count, so a half-typed
        // answer still reads as idle: the newline completes it.
        let mut queued: libc::c_int = 0;
        match unsafe { libc::ioctl(fd, libc::TIOCINQ, &mut queued) } {
            0 if queued == 0 => TtyState::Idle,
            0 => TtyState::LineQueued,
            _ => TtyState::Background,
        }
    }

    /// Drop unread input, e.g. a pushed newline the host did not consume.
    pub fn flush_input(&self) {
        unsafe { libc::tcflush(self.fd.as_raw_fd(), libc::TCIFLUSH) };
    }

    /// Best-effort message to the user, bypassing the host.
    pub fn notice(&self, msg: &str) {
        self.write(&format!("\r\n{msg}\r\n"));
    }

    /// Show `text` at the right end of the cursor's line, in place of what
    /// the last call showed there, and put the cursor back: a status beside a
    /// prompt that is still being typed into, which a new line would make
    /// look like a fresh one. Cut to half the terminal's width, so that it
    /// doesn't wrap and, beside any reasonable prompt, doesn't cover it.
    /// Nothing on a terminal without cursor control.
    pub fn aside(&self, text: &str) {
        let mut size: libc::winsize = unsafe { std::mem::zeroed() };
        if !self.vt || unsafe { libc::ioctl(self.fd.as_raw_fd(), libc::TIOCGWINSZ, &mut size) } < 0
        {
            return;
        }
        let columns = usize::from(size.ws_col);
        if columns < 40 {
            return;
        }
        let (shown, width) = fit(text, columns / 2);
        // Save the cursor, clear the rest of its line (the last aside), write
        // so as to end one column short of the edge, restore the cursor.
        let column = columns - width;
        self.write(&format!("\x1b7\x1b[K\x1b[{column}G{shown}\x1b8"));
    }

    fn write(&self, s: &str) {
        unsafe { libc::write(self.fd.as_raw_fd(), s.as_ptr().cast(), s.len()) };
    }
}

/// `text` as one line of at most `max` columns, and its width. Control
/// characters, which could move the cursor, become spaces; the width of a
/// character from U+1100 up is taken to be 2 (East Asian wide), which may
/// overestimate but never underestimates.
fn fit(text: &str, max: usize) -> (String, usize) {
    let cols = |c: char| if c >= '\u{1100}' { 2 } else { 1 };
    let mut out = String::new();
    let mut width = 0;
    let total: usize = text.chars().map(cols).sum();
    let budget = if total > max { max - 1 } else { max };
    for c in text.chars() {
        let c = if c.is_control() { ' ' } else { c };
        if width + cols(c) > budget {
            out.push('…');
            return (out, width + 1);
        }
        width += cols(c);
        out.push(c);
    }
    (out, width)
}

#[cfg(test)]
mod tests {
    use super::fit;

    #[test]
    fn an_aside_is_one_line_within_its_width() {
        assert_eq!(
            fit("finger: timed out", 40),
            ("finger: timed out".into(), 17)
        );
        assert_eq!(fit("a\x1b[2Jb\nc", 40), ("a [2Jb c".into(), 8));
        assert_eq!(fit("abcdefghij", 5), ("abcd…".into(), 5));
        // Wide characters count double, so the cut leaves room for them.
        assert_eq!(fit("指紋認証がタイムアウト", 9), ("指紋認証…".into(), 9));
    }
}
