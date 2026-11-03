//! Spawning and reaping `pam-race-helper` processes.
//!
//! Each helper runs under a **keeper**: a child created with raw
//! `clone3(CLONE_PIDFD)` (or `clone()`, see [`clone_process`]) and
//! `exit_signal = 0` that never execs (execve() would reset its exit signal
//! to SIGCHLD). So from the host's point of view:
//!
//! * No SIGCHLD ever arrives, and the host's `waitpid(-1)`, `SIGCHLD =
//!   SIG_IGN` or `SA_NOCLDWAIT` can neither reap nor auto-reap the keeper:
//!   both only apply to children whose exit signal is SIGCHLD (short of
//!   `__WALL`). The keeper is only reaped by us, through its pidfd.
//! * The keeper is a child subreaper. It forks the helper into a process
//!   group of its own, and it is the one that kills that group, then reaps
//!   the helper and every member orphaned on the way before it exits. So
//!   nothing the helper started is left for the host to reap, not even when
//!   the host is a subreaper itself (where orphans would otherwise go).
//! * The group kill is safe: the keeper only reaps the helper after it, so
//!   the helper's PID, which is the group's ID, cannot have been recycled.
//! * The keeper exits once the helper is gone, so its pidfd turns readable
//!   then, whoever else may still hold the helper's socket.
//!
//! The keeper ends the helper when the helper exits on its own (killing what
//! it left in its group) or when asked to: dropping a [`Child`] sends the
//! keeper SIGTERM, and kills it outright only if it has not finished within
//! [`KEEPER_GRACE`] (a group member stuck in uninterruptible sleep, say).
//!
//! The keeper is a copy of a possibly multi-threaded host that never execs:
//! like the helper before its execve(), it only issues async-signal-safe
//! syscalls on memory prepared before the clone, and it runs with every
//! signal blocked so no host handler can ever run in it. It takes SIGCHLD
//! and SIGTERM with sigwaitinfo().

use std::ffi::{CStr, CString};
use std::io;
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;
use std::time::{Duration, Instant};

use libc::{c_char, c_int};

use crate::types::{AbsPath, LocaleEnv};

/// File descriptor the helper finds its socket on.
pub const HELPER_FD: RawFd = 3;

/// The helper's environment is `PATH` plus the [`LocaleEnv`] entries the
/// caller passes; everything else is dropped.
const DEFAULT_PATH: &CStr = c"PATH=/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin";

/// How long a keeper asked to end its helper may take before it is killed,
/// which leaves the helper's group to fend for itself.
pub const KEEPER_GRACE: Duration = Duration::from_secs(1);

/// A running helper, owned: dropping it has the keeper kill the helper's
/// process group, then reaps the keeper.
pub struct Child {
    /// The keeper's PID (also the session ID of the helper), for logs.
    pub pid: libc::pid_t,
    pidfd: OwnedFd,
    pub sock: OwnedFd,
}

/// Everything the forked child needs, allocated before clone.
pub struct ExecImage {
    path: CString,
    argv: [*const c_char; 2],
    _env: Vec<LocaleEnv>,
    envp: Vec<*const c_char>,
}

impl ExecImage {
    pub fn new(path: &AbsPath, env: Vec<LocaleEnv>) -> ExecImage {
        let path = path.as_cstr().to_owned();
        let envp = [DEFAULT_PATH]
            .into_iter()
            .chain(env.iter().map(LocaleEnv::as_cstr))
            .map(CStr::as_ptr)
            .chain([ptr::null()])
            .collect();
        ExecImage {
            argv: [path.as_ptr(), ptr::null()],
            path,
            _env: env,
            envp,
        }
    }
}

fn cvt(r: c_int) -> io::Result<c_int> {
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

/// Duplicate `fd` to a CLOEXEC descriptor >= 10, so that in the child the
/// dup2() onto 0..=3 can never clobber it.
fn high_fd(fd: RawFd) -> io::Result<OwnedFd> {
    let n = cvt(unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(n) })
}

pub fn spawn(image: &ExecImage) -> io::Result<Child> {
    let mut sv = [0 as c_int; 2];
    cvt(unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        )
    })?;
    let (ours, theirs) = unsafe { (OwnedFd::from_raw_fd(sv[0]), OwnedFd::from_raw_fd(sv[1])) };
    let theirs = high_fd(theirs.as_raw_fd())?;
    let devnull = {
        let fd = cvt(unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) })?;
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        high_fd(fd.as_raw_fd())?
    };
    let host = unsafe { libc::getpid() };

    // Block every signal across clone so no host handler can run in the
    // keeper, which keeps it that way. The mask is restored right after.
    let mut all: libc::sigset_t = unsafe { mem::zeroed() };
    let mut old: libc::sigset_t = unsafe { mem::zeroed() };
    unsafe {
        libc::sigfillset(&mut all);
        libc::pthread_sigmask(libc::SIG_SETMASK, &all, &mut old);
    }

    let mut pidfd: c_int = -1;
    let pid = unsafe { clone_process(0, Some(&mut pidfd)) };
    if pid == 0 {
        unsafe { keeper(image, theirs.as_raw_fd(), devnull.as_raw_fd(), host) }
    }
    let err = io::Error::last_os_error();
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old, ptr::null_mut()) };
    if pid < 0 {
        return Err(err);
    }
    Ok(Child {
        pid: pid as libc::pid_t,
        pidfd: unsafe { OwnedFd::from_raw_fd(pidfd) },
        sock: ours,
    })
}

/// A fork-like clone (no shared memory) sending `exit_signal` to the parent
/// on exit (0: none), with CLONE_PIDFD into `pidfd` if given. clone3() first;
/// clone() where a seccomp filter fails clone3 with ENOSYS, as container
/// runtimes do so that glibc falls back too. Async-signal-safe.
unsafe fn clone_process(exit_signal: c_int, pidfd: Option<&mut c_int>) -> libc::c_long {
    let (flags, pidfd): (u64, *mut c_int) = match pidfd {
        Some(p) => (libc::CLONE_PIDFD as u64, p),
        None => (0, ptr::null_mut()),
    };
    let mut args: libc::clone_args = unsafe { mem::zeroed() };
    args.flags = flags;
    args.pidfd = pidfd as u64;
    args.exit_signal = exit_signal as u64;
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &mut args as *mut libc::clone_args,
            mem::size_of::<libc::clone_args>(),
        )
    };
    if pid >= 0 || unsafe { *libc::__errno_location() } != libc::ENOSYS {
        return pid;
    }
    // clone(flags | exit signal, stack, parent_tid, ...): with CLONE_PIDFD,
    // parent_tid receives the pidfd. The remaining arguments are 0, which
    // also covers the architectures that swap the last two; s390x swaps the
    // first two.
    let flags = flags as libc::c_ulong | exit_signal as libc::c_ulong;
    let stack: libc::c_ulong = 0;
    let zero: libc::c_ulong = 0;
    #[cfg(not(target_arch = "s390x"))]
    let pid = unsafe { libc::syscall(libc::SYS_clone, flags, stack, pidfd, zero, zero) };
    #[cfg(target_arch = "s390x")]
    let pid = unsafe { libc::syscall(libc::SYS_clone, stack, flags, pidfd, zero, zero) };
    pid
}

/// Exit status of a keeper or helper that could not set itself up.
const SETUP_FAILED: c_int = 126;

/// Runs in the cloned child. Async-signal-safe calls only; never returns.
unsafe fn keeper(image: &ExecImage, sock: RawFd, devnull: RawFd, host: libc::pid_t) -> ! {
    let ok = |r: c_int| {
        if r < 0 {
            unsafe { libc::_exit(SETUP_FAILED) }
        }
    };
    unsafe {
        // Die with the thread that is running pam_authenticate().
        ok(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL));
        if libc::getppid() != host {
            libc::_exit(SETUP_FAILED);
        }
        // Descendants of the helper whose parent dies come to us, not to the
        // host (or whichever subreaper is above it).
        ok(libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1));
        // Dispositions survive clone, and a host's SIGCHLD = SIG_IGN or
        // SA_NOCLDWAIT would have the helper auto-reaped, freeing the ID of
        // the group we are going to kill. (The signal stays blocked.)
        let mut dfl: libc::sigaction = mem::zeroed();
        dfl.sa_sigaction = libc::SIG_DFL;
        ok(libc::sigaction(libc::SIGCHLD, &dfl, ptr::null_mut()));
        // Own session: no controlling terminal, so no module can read the
        // user's keystrokes or be hit by terminal-generated signals. All I/O
        // goes through the conversation socket.
        ok(libc::setsid());
        for fd in 0..=2 {
            ok(libc::dup2(devnull, fd));
        }
        ok(libc::dup2(sock, HELPER_FD));
        // Everything else, including host descriptors lacking O_CLOEXEC.
        ok(libc::syscall(libc::SYS_close_range, HELPER_FD + 1, u32::MAX, 0) as c_int);
        ok(libc::chdir(c"/".as_ptr()));
        let me = libc::getpid();
        let helper = clone_process(libc::SIGCHLD, None) as libc::pid_t;
        if helper == 0 {
            exec_helper(image, me);
        }
        // The keeper holds nothing: the socket's EOF is the helper's alone.
        libc::syscall(libc::SYS_close_range, 0, u32::MAX, 0);
        ok(helper);
        // A process group of its own, so that it can be killed with all it
        // started but without us. The helper does the same before it execs;
        // whichever comes first (this one fails once it has exec'd).
        libc::setpgid(helper, helper);
        wait_for_end(helper);
        end(helper)
    }
}

/// Returns once the helper has exited or we are asked to end it (SIGTERM).
/// Async-signal-safe.
unsafe fn wait_for_end(helper: libc::pid_t) {
    unsafe {
        let mut set: libc::sigset_t = mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGCHLD);
        libc::sigaddset(&mut set, libc::SIGTERM);
        loop {
            // Only a peek (WNOWAIT): the helper stays unreaped, so its ID,
            // which is also its group's, stays reserved for the group kill.
            let mut info: libc::siginfo_t = mem::zeroed();
            let flags = libc::WEXITED | libc::WNOHANG | libc::WNOWAIT;
            if libc::waitid(libc::P_PID, helper as libc::id_t, &mut info, flags) < 0
                || info.si_pid() != 0
            {
                return;
            }
            // SIGCHLD may also come from an orphan reparented to us: look
            // again. Every signal is blocked, so nothing interrupts the wait.
            match libc::sigwaitinfo(&set, ptr::null_mut()) {
                libc::SIGTERM => return,
                sig if sig < 0 && *libc::__errno_location() != libc::EINTR => return,
                _ => {}
            }
        }
    }
}

/// Kill everything the helper started, reap it all, and exit.
/// Async-signal-safe.
unsafe fn end(helper: libc::pid_t) -> ! {
    unsafe {
        // The helper's group in one go, so its members cannot fork past it.
        // Nothing is reaped yet, so the group's ID is still the helper's.
        libc::kill(-helper, libc::SIGKILL);
        // In case it died in setup, before it had a group of its own.
        libc::kill(helper, libc::SIGKILL);
        // Then whatever left the group (pam_exec's children setsid()). As a
        // subreaper we inherit every descendant whose parent dies, so killing
        // our children until none is left kills them all.
        let mut sigchld: libc::sigset_t = mem::zeroed();
        libc::sigemptyset(&mut sigchld);
        libc::sigaddset(&mut sigchld, libc::SIGCHLD);
        let tick = libc::timespec {
            tv_sec: 0,
            tv_nsec: 10_000_000,
        };
        loop {
            if !reap_dead() {
                libc::_exit(0);
            }
            if !kill_children() {
                // No /proc: the group at least. A member is reparented to us
                // before its dead parent can be reaped, so once none is our
                // child, none is left.
                let mut info: libc::siginfo_t = mem::zeroed();
                let all = libc::WEXITED | libc::__WALL;
                while libc::waitid(libc::P_PGID, helper as libc::id_t, &mut info, all) == 0 {}
                reap_dead();
                libc::_exit(0);
            }
            libc::sigtimedwait(&sigchld, ptr::null_mut(), &tick);
        }
    }
}

/// Reap every dead child; false once there are no children at all.
/// Async-signal-safe.
unsafe fn reap_dead() -> bool {
    loop {
        let mut info: libc::siginfo_t = unsafe { mem::zeroed() };
        let flags = libc::WEXITED | libc::WNOHANG | libc::__WALL;
        if unsafe { libc::waitid(libc::P_ALL, 0, &mut info, flags) } < 0 {
            return unsafe { *libc::__errno_location() } != libc::ECHILD;
        }
        if unsafe { info.si_pid() } == 0 {
            return true;
        }
    }
}

/// SIGKILL every child of ours, as listed in /proc; false if that list
/// cannot be read. Unreaped children cannot have recycled PIDs.
/// Async-signal-safe.
unsafe fn kill_children() -> bool {
    let fd = unsafe {
        libc::open(
            c"/proc/thread-self/children".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return false;
    }
    let mut buf = [0u8; 512];
    let mut pid: libc::pid_t = 0;
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            break;
        }
        // Decimal PIDs separated by spaces, possibly split across reads.
        for &b in &buf[..n as usize] {
            if b.is_ascii_digit() {
                pid = pid
                    .saturating_mul(10)
                    .saturating_add(libc::pid_t::from(b - b'0'));
            } else if pid != 0 {
                unsafe { libc::kill(pid, libc::SIGKILL) };
                pid = 0;
            }
        }
    }
    if pid != 0 {
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    unsafe { libc::close(fd) };
    true
}

/// Runs in the keeper's child. Async-signal-safe calls only; never returns.
unsafe fn exec_helper(image: &ExecImage, keeper: libc::pid_t) -> ! {
    let ok = |r: c_int| {
        if r < 0 {
            unsafe { libc::_exit(SETUP_FAILED) }
        }
    };
    unsafe {
        ok(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL));
        if libc::getppid() != keeper {
            libc::_exit(SETUP_FAILED);
        }
        // See keeper(): it must not exec outside its own group.
        ok(libc::setpgid(0, 0));
        // execve() resets handlers but keeps SIG_IGN dispositions and the
        // mask; give the helper pristine signal state. glibc refuses its two
        // internal signals (32, 33) with EINVAL; they are not ignorable.
        let mut dfl: libc::sigaction = mem::zeroed();
        dfl.sa_sigaction = libc::SIG_DFL;
        for sig in 1..=libc::SIGRTMAX() {
            if sig != libc::SIGKILL && sig != libc::SIGSTOP {
                libc::sigaction(sig, &dfl, ptr::null_mut());
            }
        }
        let mut none: libc::sigset_t = mem::zeroed();
        libc::sigemptyset(&mut none);
        ok(libc::sigprocmask(libc::SIG_SETMASK, &none, ptr::null_mut()));
        libc::execve(
            image.path.as_ptr(),
            image.argv.as_ptr(),
            image.envp.as_ptr(),
        );
        libc::_exit(127);
    }
}

impl Child {
    /// Readable once the helper and everything it started are gone.
    pub fn exit_fd(&self) -> BorrowedFd<'_> {
        self.pidfd.as_fd()
    }

    /// Signal the keeper; false if that failed (it may be gone already).
    fn signal(&self, sig: c_int) -> bool {
        let r = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                sig,
                ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        r == 0
    }

    /// Whether the keeper exits within `grace`.
    fn exits_within(&self, grace: Duration) -> bool {
        let deadline = Instant::now() + grace;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let mut p = libc::pollfd {
                fd: self.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ms = left.as_millis().try_into().unwrap_or(c_int::MAX);
            match unsafe { libc::poll(&mut p, 1, ms) } {
                0 => return false,
                n if n > 0 => return true,
                _ if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => {}
                _ => return false,
            }
        }
    }
}

impl Drop for Child {
    /// Have the keeper end the helper (see the module documentation), then
    /// reap the keeper.
    fn drop(&mut self) {
        if !self.signal(libc::SIGTERM) || !self.exits_within(KEEPER_GRACE) {
            self.signal(libc::SIGKILL);
        }
        let mut info: libc::siginfo_t = unsafe { mem::zeroed() };
        while unsafe {
            libc::waitid(
                libc::P_PIDFD,
                self.pidfd.as_raw_fd() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::__WALL,
            )
        } < 0
            && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
        {}
    }
}
