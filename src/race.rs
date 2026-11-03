//! Imperative shell around [`Arbiter`]: processes, sockets, threads, the
//! host conversation and the terminal.
//!
//! The thread that called `pam_sm_authenticate` (the "host thread") is the
//! only one that touches the PAM handle or calls the host's conversation
//! function, because hosts assume both happen on their own thread (sudo's
//! password reader relies on its signal handlers interrupting that very
//! `read()`). A watcher thread, with every signal blocked so host signal
//! delivery is unaffected, reads the helper sockets and feeds the arbiter;
//! if the host thread is stuck in a prompt the arbiter no longer needs (the
//! race is decided, or the helper that asked is gone), it carries out the
//! arbiter's release of that prompt through the terminal.

use std::fmt;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Instant;
use std::{io, mem, ptr, thread};

use crate::arbiter::{AfterPrompt, Arbiter, HostStep, Obsolete, Outcome, Release};
use crate::config::Config;
use crate::ffi::*;
use crate::proto::{self, FromHelper, ProtoError};
use crate::spawn::{self, Child, ExecImage};
use crate::tty::Terminal;
use crate::types::*;
use crate::{Log, wire};

/// PAM items forwarded to the sub-stacks.
pub struct Items {
    pub tty: Option<ItemValue>,
    pub rhost: Option<ItemValue>,
    pub ruser: Option<ItemValue>,
}

pub fn run(
    conv: HostConv<'_>,
    cfg: &Config,
    log: &Log,
    flags: AuthFlags,
    user: UserName,
    items: Items,
) -> PamResult {
    let image = ExecImage::new(&cfg.helper, locale_env(log));
    let mut children: Vec<Child> = Vec::with_capacity(cfg.services.len());
    for service in &cfg.services {
        let setup = proto::Setup {
            flags,
            service: service.clone(),
            user: user.clone(),
            tty: items.tty.clone(),
            rhost: items.rhost.clone(),
            ruser: items.ruser.clone(),
            confdir: cfg.confdir.clone(),
        };
        let started = spawn::spawn(&image).and_then(|c| {
            // Owned before anything else can fail: dropping a Child kills and
            // reaps it.
            children.push(c);
            let c = children.last().expect("just pushed");
            wire::send(c.sock.as_fd(), &proto::encode_setup(&setup)).map(|()| c.pid)
        });
        match started {
            Ok(pid) => log.debug(format_args!("started {service} as pid {pid}")),
            Err(e) => {
                log.err(format_args!(
                    "cannot start {} for {service}: {e}",
                    cfg.helper
                ));
                return Err(PamError::SYSTEM_ERR);
            }
        }
    }
    let stop = eventfd().map_err(|e| {
        log.err(format_args!("eventfd: {e}"));
        PamError::SYSTEM_ERR
    })?;
    let shared = Shared {
        arbiter: Mutex::new(Arbiter::new(children.len(), Instant::now() + cfg.settle)),
        changed: Condvar::new(),
    };
    let tty = Terminal::open();

    let result = thread::scope(|s| {
        // Wakes the watcher once the host thread is done, also by unwinding:
        // the scope joins the watcher even on a panic.
        let _stop = Stop(stop.as_fd());
        let watcher = Watcher {
            children: &children,
            cfg,
            shared: &shared,
            tty: tty.as_ref(),
            log,
        };
        let stop_fd = stop.as_fd();
        let spawned = {
            // Created with every signal blocked: the watcher must never take a
            // signal the host expects on its own thread.
            let _blocked = SignalsBlocked::new();
            thread::Builder::new()
                .name("pam_race".into())
                .stack_size(256 << 10)
                .spawn_scoped(s, move || watcher.run(stop_fd))
        };
        if let Err(e) = spawned {
            log.err(format_args!("cannot start watcher thread: {e}"));
            return Err(PamError::SYSTEM_ERR);
        }
        Host {
            conv,
            children: &children,
            shared: &shared,
            tty: tty.as_ref(),
            log,
        }
        .run()
    });
    drop(children);
    log.debug(format_args!("result {}", pam_code(result)));
    result
}

/// The locale variables to hand to the helpers; values that are not plain
/// locale names are dropped.
fn locale_env(log: &Log) -> Vec<LocaleEnv> {
    LocaleVar::ALL
        .into_iter()
        .filter_map(|var| {
            let value = std::env::var_os(var.name())?;
            let parsed = LocaleEnv::parse(var, value.as_bytes());
            if parsed.is_none() {
                log.debug(format_args!("not passing {}: {value:?}", var.name()));
            }
            parsed
        })
        .collect()
}

struct Shared {
    arbiter: Mutex<Arbiter>,
    changed: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Arbiter> {
        self.arbiter.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Blocks every signal on the current thread until dropped.
struct SignalsBlocked(libc::sigset_t);

impl SignalsBlocked {
    fn new() -> Self {
        unsafe {
            let mut all: libc::sigset_t = mem::zeroed();
            let mut old: libc::sigset_t = mem::zeroed();
            libc::sigfillset(&mut all);
            libc::pthread_sigmask(libc::SIG_SETMASK, &all, &mut old);
            SignalsBlocked(old)
        }
    }
}

impl Drop for SignalsBlocked {
    fn drop(&mut self) {
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.0, ptr::null_mut()) };
    }
}

fn eventfd() -> io::Result<OwnedFd> {
    match unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) } {
        fd if fd >= 0 => Ok(unsafe { OwnedFd::from_raw_fd(fd) }),
        _ => Err(io::Error::last_os_error()),
    }
}

/// Signals the stop eventfd when dropped.
struct Stop<'a>(BorrowedFd<'a>);

impl Drop for Stop<'_> {
    fn drop(&mut self) {
        let one: u64 = 1;
        unsafe { libc::write(self.0.as_raw_fd(), (&raw const one).cast(), 8) };
    }
}

// ------------------------------------------------------- host conversation

/// The host application's conversation function.
pub struct HostConv<'a>(&'a pam_conv);

impl HostConv<'_> {
    /// # Safety
    /// `pamh` must be the live handle passed to the module; the result must
    /// not outlive the module call.
    pub unsafe fn of<'a>(pamh: *mut pam_handle_t) -> Option<HostConv<'a>> {
        let mut p: *const libc::c_void = ptr::null();
        if unsafe { pam_get_item(pamh, PAM_CONV, &mut p) } != PAM_SUCCESS || p.is_null() {
            return None;
        }
        let conv = unsafe { &*(p as *const pam_conv) };
        conv.conv.is_some().then_some(HostConv(conv))
    }

    fn converse(&self, msgs: &Messages) -> Result<Responses, PamError> {
        let f = self.0.conv.expect("checked in HostConv::of");
        let structs: Vec<pam_message> = msgs
            .as_slice()
            .iter()
            .map(|m| pam_message {
                msg_style: m.style.raw(),
                msg: m.text.as_cstr().as_ptr(),
            })
            .collect();
        // Pointers into one contiguous array: valid under both the Linux-PAM
        // (msg[i]) and the Solaris ((*msg)[i]) interpretation.
        let mut ptrs: Vec<*const pam_message> = structs.iter().map(|m| m as *const _).collect();
        let mut resp: *mut pam_response = ptr::null_mut();
        let rc = unsafe {
            f(
                msgs.len() as libc::c_int,
                ptrs.as_mut_ptr(),
                &mut resp,
                self.0.appdata_ptr,
            )
        };
        // Own whatever came back before looking at rc, so it is wiped and
        // freed on every path.
        let answers = unsafe { take_responses(resp, msgs.len()) };
        pam_result(rc)?;
        // An answer too long to forward is as unusable as a failed call.
        Responses::parse(answers, msgs).ok_or(PamError::CONV_ERR)
    }
}

/// Move a malloc'd `pam_response` array into wiped memory and free it.
unsafe fn take_responses(resp: *mut pam_response, n: usize) -> Vec<Option<Secret>> {
    if resp.is_null() {
        return (0..n).map(|_| None).collect();
    }
    let out = (0..n)
        .map(|i| {
            let r = unsafe { (*resp.add(i)).resp };
            (!r.is_null()).then(|| unsafe {
                let len = libc::strlen(r);
                let s = Secret::new(std::slice::from_raw_parts(r.cast::<u8>(), len).to_vec());
                libc::explicit_bzero(r.cast(), len);
                libc::free(r.cast());
                s
            })
        })
        .collect();
    unsafe { libc::free(resp.cast()) };
    out
}

// -------------------------------------------------------------- host thread

struct Host<'a> {
    conv: HostConv<'a>,
    children: &'a [Child],
    shared: &'a Shared,
    tty: Option<&'a Terminal>,
    log: &'a Log,
}

impl Host<'_> {
    fn run(&self) -> PamResult {
        let mut arb = self.shared.lock();
        loop {
            arb = match arb.next_for_host(Instant::now()) {
                HostStep::Finish(r) => return r,
                HostStep::Wait(None) => self
                    .shared
                    .changed
                    .wait(arb)
                    .unwrap_or_else(|e| e.into_inner()),
                HostStep::Wait(Some(until)) => {
                    let left = until.saturating_duration_since(Instant::now());
                    self.shared
                        .changed
                        .wait_timeout(arb, left)
                        .unwrap_or_else(|e| e.into_inner())
                        .0
                }
                HostStep::Show(_, msgs) => {
                    drop(arb);
                    if let Err(e) = self.conv.converse(&msgs) {
                        self.log.debug(format_args!("{e} showing a message"));
                    }
                    self.shared.lock()
                }
                HostStep::Ask(h, msgs) => {
                    drop(arb);
                    let answer = self.conv.converse(&msgs);
                    let mut arb = self.shared.lock();
                    let ret = arb.prompt_returned(h, answer);
                    if ret.flush_input {
                        // Under the lock, so the watcher cannot push again.
                        self.tty
                            .expect("only pushed through a terminal")
                            .flush_input();
                    }
                    self.shared.changed.notify_all();
                    match ret.action {
                        AfterPrompt::Discard => arb,
                        AfterPrompt::Reply(h, resps) => {
                            drop(arb);
                            let sent = wire::send(
                                self.children[h.0].sock.as_fd(),
                                proto::encode_reply(&resps).as_bytes(),
                            );
                            let mut arb = self.shared.lock();
                            if let Err(e) = sent {
                                // The helper may well be alive, waiting for
                                // this reply forever: it is out of the race.
                                self.log.err(format_args!("reply: {e}"));
                                arb.helper_finished(h, Err(PamError::SYSTEM_ERR));
                                self.shared.changed.notify_all();
                            }
                            arb
                        }
                    }
                }
            };
        }
    }
}

// ------------------------------------------------------------------ watcher

enum Fault {
    Exited,
    Io(io::Error),
    Proto(ProtoError),
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fault::Exited => f.write_str("helper exited without a result"),
            Fault::Io(e) => e.fmt(f),
            Fault::Proto(e) => e.fmt(f),
        }
    }
}

/// The next event from a helper whose socket or exit fd (`exited`) is ready,
/// or None if there is nothing to act on yet.
///
/// The socket is always drained before the exit counts: poll() checks the
/// two fds one after the other, so a single pass can find the socket still
/// empty and then the exit, although the helper queued its result before
/// exiting. Hence a non-blocking read whenever either fd is ready.
fn helper_event(
    sock: BorrowedFd<'_>,
    exited: bool,
    buf: &mut [u8],
) -> Option<Result<FromHelper, Fault>> {
    match wire::try_recv(sock, buf) {
        Ok(Some(pkt)) => Some(proto::decode_from_helper(pkt).map_err(Fault::Proto)),
        Ok(None) => Some(Err(Fault::Exited)),
        // Gone, but something it started still holds the socket.
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => exited.then_some(Err(Fault::Exited)),
        // It died with our Setup still unread (e.g. exec failed).
        Err(e) if e.kind() == io::ErrorKind::ConnectionReset => Some(Err(Fault::Exited)),
        Err(e) => Some(Err(Fault::Io(e))),
    }
}

struct Watcher<'a> {
    children: &'a [Child],
    cfg: &'a Config,
    shared: &'a Shared,
    tty: Option<&'a Terminal>,
    log: &'a Log,
}

/// A panicking watcher must not leave the host thread waiting forever for
/// news: nothing more will be heard from any helper.
struct AbandonOnPanic<'a>(&'a Shared);

impl Drop for AbandonOnPanic<'_> {
    fn drop(&mut self) {
        if thread::panicking() {
            self.0.lock().abandon(PamError::SYSTEM_ERR);
            self.0.changed.notify_all();
        }
    }
}

impl Watcher<'_> {
    /// Feed helper events to the arbiter and release prompts it no longer
    /// needs, until the host thread is done (the stop fd). Reading goes on
    /// after the race is decided: the arbiter knows what to drop.
    fn run(self, stop: BorrowedFd<'_>) {
        let _abandon = AbandonOnPanic(self.shared);
        let mut buf = vec![0u8; proto::MAX_PACKET];
        let mut open: Vec<HelperId> = (0..self.children.len()).map(HelperId).collect();
        let mut fds = Vec::with_capacity(2 * open.len() + 1);
        // When the release of the host's prompt is due for its next step.
        let mut release_at: Option<Instant> = None;
        loop {
            fds.clear();
            fds.push(libc::pollfd {
                fd: stop.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
            // The exit fd also catches a helper that died while something
            // it started still holds its socket open, so no EOF comes.
            for h in &open {
                let c = &self.children[h.0];
                for fd in [c.sock.as_raw_fd(), c.exit_fd().as_raw_fd()] {
                    fds.push(libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    });
                }
            }
            let timeout = release_at.map_or(-1, poll_timeout);
            if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) } < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                self.log.err(format_args!("poll: {e}"));
                self.shared.lock().abandon(PamError::SYSTEM_ERR);
                self.shared.changed.notify_all();
                return;
            }
            if fds[0].revents != 0 {
                return;
            }
            let ready: Vec<(HelperId, bool)> = fds[1..]
                .chunks(2)
                .zip(&open)
                .filter(|(p, _)| p[0].revents != 0 || p[1].revents != 0)
                .map(|(p, &h)| (h, p[1].revents != 0))
                .collect();
            for (h, exited) in ready {
                let Some(event) = self.read(h, exited, &mut buf) else {
                    continue;
                };
                if !matches!(event, Ok(FromHelper::Conv(_))) {
                    open.retain(|&o| o != h);
                }
                self.handle(h, event);
            }
            release_at = self.release(Instant::now());
        }
    }

    fn name(&self, h: HelperId) -> &ServiceName {
        &self.cfg.services[h.0]
    }

    /// What helper `h` has to say now that one of its fds is ready.
    fn read(&self, h: HelperId, exited: bool, buf: &mut [u8]) -> Option<Result<FromHelper, Fault>> {
        helper_event(self.children[h.0].sock.as_fd(), exited, buf)
    }

    fn handle(&self, h: HelperId, event: Result<FromHelper, Fault>) {
        let decided = match event {
            Ok(FromHelper::Conv(msgs)) => {
                self.log
                    .debug(format_args!("{}: {} message(s)", self.name(h), msgs.len()));
                self.shared.lock().helper_said(h, msgs);
                None
            }
            Ok(FromHelper::Done(r)) => {
                self.log
                    .debug(format_args!("{} returned {}", self.name(h), pam_code(r)));
                self.shared.lock().helper_finished(h, r)
            }
            Err(fault) => {
                self.log.err(format_args!("{}: {fault}", self.name(h)));
                self.shared
                    .lock()
                    .helper_finished(h, Err(PamError::SYSTEM_ERR))
            }
        };
        self.shared.changed.notify_all();
        if let Some(Outcome::Won(w)) = decided {
            self.log
                .notice(format_args!("authenticated by {}", self.name(w)));
        }
    }

    /// Carry out the arbiter's release of the host's prompt as far as it
    /// goes at `now`; returns when it is due again.
    fn release(&self, now: Instant) -> Option<Instant> {
        let tty = self.tty?;
        let mut arb = self.shared.lock();
        loop {
            match arb.release_step(now, tty.state()) {
                Release::Idle(at) => return at,
                Release::Push => match tty.push_newline() {
                    Ok(()) => arb.newline_pushed(),
                    Err(e) => {
                        self.log.debug(format_args!("TIOCSTI: {e}"));
                        arb.push_failed();
                    }
                },
                Release::GiveUp { flush, notice } => {
                    // Under the lock: the host thread cannot be flushing or
                    // reading the arbiter meanwhile.
                    if flush {
                        tty.flush_input();
                    }
                    if let Some(why) = notice {
                        tty.notice(&self.press_enter(why));
                    }
                }
            }
        }
    }

    fn press_enter(&self, why: Obsolete) -> String {
        let what = match why {
            Obsolete::Decided(Outcome::Won(w)) => format!("Authenticated by {}", self.name(w)),
            Obsolete::Decided(Outcome::Lost { .. } | Outcome::Cancelled(_)) => {
                "Authentication failed".into()
            }
            Obsolete::HelperGone(h) => format!("{} stopped", self.name(h)),
        };
        format!("{what}. Press Enter to continue.")
    }
}

/// Milliseconds from now until `at`, rounded up, for poll().
fn poll_timeout(at: Instant) -> libc::c_int {
    let left = at.saturating_duration_since(Instant::now());
    left.as_nanos()
        .div_ceil(1_000_000)
        .try_into()
        .unwrap_or(libc::c_int::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (OwnedFd, OwnedFd) {
        let mut sv = [0; 2];
        let r = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                sv.as_mut_ptr(),
            )
        };
        assert_eq!(r, 0);
        unsafe { (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1])) }
    }

    #[test]
    fn a_result_queued_before_exit_wins_over_the_exit() {
        let mut buf = vec![0u8; proto::MAX_PACKET];
        let (ours, theirs) = pair();
        wire::send(theirs.as_fd(), &proto::encode_done(Ok(()))).unwrap();
        drop(theirs);
        // Exit seen while the socket was still reported empty.
        assert!(matches!(
            helper_event(ours.as_fd(), true, &mut buf),
            Some(Ok(FromHelper::Done(Ok(()))))
        ));
        assert!(matches!(
            helper_event(ours.as_fd(), true, &mut buf),
            Some(Err(Fault::Exited))
        ));
    }

    #[test]
    fn an_exit_with_the_socket_held_elsewhere_is_still_an_exit() {
        let mut buf = vec![0u8; proto::MAX_PACKET];
        let (ours, _held_by_a_descendant) = pair();
        assert!(matches!(
            helper_event(ours.as_fd(), true, &mut buf),
            Some(Err(Fault::Exited))
        ));
        assert!(
            helper_event(ours.as_fd(), false, &mut buf).is_none(),
            "neither exited nor anything to read"
        );
    }
}
