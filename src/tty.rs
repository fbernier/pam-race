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

pub struct Terminal(OwnedFd);

impl Terminal {
    /// The calling process's controlling terminal, if any.
    pub fn open() -> Option<Terminal> {
        let fd = unsafe {
            libc::open(
                c"/dev/tty".as_ptr(),
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        (fd >= 0).then(|| Terminal(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    /// Queue a newline as if typed.
    pub fn push_newline(&self) -> io::Result<()> {
        let c: libc::c_char = b'\n' as _;
        if unsafe { libc::ioctl(self.0.as_raw_fd(), libc::TIOCSTI, &c) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// What a pushed newline would run into. Any error reads as
    /// [`TtyState::Background`]: nothing is pushed into a terminal we cannot
    /// see.
    pub fn state(&self) -> TtyState {
        let fd = self.0.as_raw_fd();
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
        unsafe { libc::tcflush(self.0.as_raw_fd(), libc::TCIFLUSH) };
    }

    /// Best-effort message to the user, bypassing the host.
    pub fn notice(&self, msg: &str) {
        let s = format!("\r\n{msg}\r\n");
        unsafe { libc::write(self.0.as_raw_fd(), s.as_ptr().cast(), s.len()) };
    }
}
