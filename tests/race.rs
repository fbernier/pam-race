//! End-to-end: a sudo-like host on a pseudo-terminal runs pam_race over
//! pam_exec-based stand-ins for "fingerprint" (no prompt, finishes on its
//! own) and "password" (prompts, checks the answer).

use std::fmt::Write as _;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const HELPER: &str = env!("CARGO_BIN_EXE_pam-race-helper");
const HOST: &str = env!("CARGO_BIN_EXE_pam-race-testhost");

/// The module under test. Cargo only copies the cdylib up to target/<profile>
/// on `cargo build`; the copy in deps/ is the one rebuilt for this test run.
fn module() -> PathBuf {
    let so = Path::new(HELPER)
        .parent()
        .unwrap()
        .join("deps/libpam_race.so");
    assert!(so.exists(), "{} missing", so.display());
    so
}

/// A fingerprint stand-in: prints a hint, then exits with `rc` after `secs`.
/// pam_exec runs it in a session of its own, so a race that loses it leaves
/// it behind unless pam_race kills what escaped the helper's process group:
/// `Race::result` checks that nothing is left.
fn finger(name: &str, secs: u32, rc: u8) -> (String, String) {
    let script =
        format!("#!/bin/sh\necho '{name}: place your finger'\n/usr/bin/sleep {secs}\nexit {rc}\n");
    (name.into(), script)
}

fn password() -> (String, String) {
    (
        "password".into(),
        "#!/bin/sh\n[ \"$(cat)\" = hunter2 ]\n".into(),
    )
}

struct Race {
    dir: PathBuf,
    child: Child,
    master: fs::File,
    out: String,
}

impl Race {
    /// Start the host on a fresh pty racing `services` (name, script).
    fn start(test: &str, services: &[(String, String)]) -> Race {
        Race::start_with(test, services, &[])
    }

    /// [`Race::start`], with the host failing a syscall (see testing/host.rs).
    fn start_denying(test: &str, services: &[(String, String)], spec: &str) -> Race {
        Race::start_with(test, services, &[("PAM_RACE_TEST_DENY", spec)])
    }

    /// [`Race::start`], with the host reading prompts like `reader` does.
    fn start_reading(test: &str, services: &[(String, String)], reader: &str) -> Race {
        let test = format!("{test}-{reader}");
        Race::start_with(&test, services, &[("PAM_RACE_TEST_READER", reader)])
    }

    /// [`Race::start`], with `env` set for the host.
    fn start_with(test: &str, services: &[(String, String)], env: &[(&str, &str)]) -> Race {
        let lib = module();
        let dir = std::env::temp_dir().join(format!("pam-race-test-{}-{test}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut names = String::new();
        for (name, script) in services {
            let path = dir.join(format!("{name}.sh"));
            fs::write(&path, script).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            let opts = if name == "password" {
                "expose_authtok quiet"
            } else {
                "stdout quiet"
            };
            fs::write(
                dir.join(name),
                format!("auth required pam_exec.so {opts} {}\n", path.display()),
            )
            .unwrap();
            write!(names, " {name}").unwrap();
        }
        fs::write(
            dir.join("race"),
            format!(
                "auth required {} helper={HELPER} confdir={} settle=1000{names}\n",
                lib.display(),
                dir.display()
            ),
        )
        .unwrap();

        let (mut m, mut s) = (0, 0);
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut m,
                    &mut s,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let (master, slave) = unsafe { (OwnedFd::from_raw_fd(m), OwnedFd::from_raw_fd(s)) };
        // The stand-in stacks never look the user up: no passwd entry needed.
        let mut cmd = Command::new(HOST);
        cmd.arg(&dir).arg("race").arg("pam-race-test");
        cmd.envs(env.iter().copied());
        cmd.stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave));
        unsafe {
            cmd.pre_exec(|| {
                // New session with the pty as controlling terminal.
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().unwrap();
        Race {
            dir,
            child,
            master: fs::File::from(master),
            out: String::new(),
        }
    }

    /// Read until `needle` shows up; returns the elapsed time.
    fn expect(&mut self, needle: &str, within: Duration) -> Duration {
        self.read_until(needle, |out| out.contains(needle), within)
    }

    /// Read until `done(output so far)`; `what` names it in failures.
    fn read_until(
        &mut self,
        what: &str,
        done: impl Fn(&str) -> bool,
        within: Duration,
    ) -> Duration {
        let start = Instant::now();
        while !done(&self.out) {
            let left = within.checked_sub(start.elapsed()).unwrap_or_else(|| {
                panic!(
                    "timed out waiting for {what:?}; output so far:\n{}",
                    self.out
                )
            });
            let mut pfd = libc::pollfd {
                fd: self.master.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut pfd, 1, left.as_millis() as i32) } <= 0 {
                continue;
            }
            let mut buf = [0u8; 4096];
            match self.master.read(&mut buf) {
                Ok(n) if n > 0 => self.out.push_str(&String::from_utf8_lossy(&buf[..n])),
                _ => panic!(
                    "pty closed waiting for {what:?}; output so far:\n{}",
                    self.out
                ),
            }
        }
        start.elapsed()
    }

    fn result(&mut self, within: Duration) -> i32 {
        let line = |out: &str| out.find("RESULT ").is_some_and(|i| out[i..].contains('\n'));
        self.read_until("RESULT line", line, within);
        assert!(
            !self.out.contains("REAPED"),
            "the host reaped a pam_race process:\n{}",
            self.out
        );
        assert!(
            self.out.contains("CHILDREN 0"),
            "pam_race returned with processes left:\n{}",
            self.out
        );
        let tail = &self.out[self.out.find("RESULT ").unwrap() + 7..];
        tail.split_whitespace().next().unwrap().parse().unwrap()
    }

    fn type_(&mut self, s: &str) {
        self.master.write_all(s.as_bytes()).unwrap();
    }
}

impl Drop for Race {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// TIOCSTI is available to root, or to anyone with legacy_tiocsti=1.
fn can_push_input() -> bool {
    let root = unsafe { libc::geteuid() } == 0;
    root || fs::read_to_string("/proc/sys/dev/tty/legacy_tiocsti").is_ok_and(|s| s.trim() == "1")
}

const PAM_SUCCESS: i32 = 0;
const PAM_SYSTEM_ERR: i32 = 4;
const PAM_CONV_ERR: i32 = 19;
const QUICK: Duration = Duration::from_secs(5);

/// The password readers the test host can imitate (see testing/host.rs): the
/// terminal handling differs, and releasing a prompt must work with both.
const READERS: [&str; 2] = ["sudo", "sudo-rs"];

#[test]
fn password_wins_while_fingerprint_pending() {
    for reader in READERS {
        let mut r = Race::start_reading("pw-wins", &[finger("finger", 30, 0), password()], reader);
        r.expect("Password: ", QUICK);
        // The settle window lets the fingerprint hint precede the prompt.
        let hint = r
            .out
            .find("finger: place your finger")
            .expect("hint not shown before prompt");
        assert!(hint < r.out.find("Password: ").unwrap(), "{}", r.out);
        r.type_("hunter2\n");
        assert_eq!(r.result(QUICK), PAM_SUCCESS, "{reader}: {}", r.out);
    }
}

#[test]
fn wrong_password_ends_the_attempt_without_waiting_for_fingerprint() {
    for reader in READERS {
        let mut r = Race::start_reading("pw-wrong", &[finger("finger", 30, 0), password()], reader);
        r.expect("Password: ", QUICK);
        r.type_("letmein\n");
        let rc = r.result(QUICK);
        assert_ne!(rc, PAM_SUCCESS, "{reader}: {}", r.out);
        assert_ne!(rc, PAM_CONV_ERR, "{reader}: {}", r.out);
    }
}

#[test]
fn fingerprint_wins_while_password_prompt_pending() {
    for reader in READERS {
        let mut r =
            Race::start_reading("finger-wins", &[finger("finger", 1, 0), password()], reader);
        r.expect("Password: ", QUICK);
        r.type_("hun"); // half-typed password must be discarded, not submitted
        if !can_push_input() {
            r.expect("Authenticated by finger. Press Enter to continue.", QUICK);
            r.type_("\n");
        }
        assert_eq!(r.result(QUICK), PAM_SUCCESS, "{reader}: {}", r.out);
    }
}

#[test]
fn a_win_behind_a_flood_of_messages_still_ends_the_prompt() {
    // Far more messages than the host takes while it sits at the prompt;
    // the success right behind them must still be seen.
    let chatty = (
        "chatty".to_string(),
        "#!/bin/sh\n/usr/bin/sleep 1\ni=0\nwhile [ $i -lt 100 ]; do echo \"chatty: $i\"; i=$((i+1)); done\n"
            .to_string(),
    );
    let mut r = Race::start("flood-wins", &[chatty, password()]);
    r.expect("Password: ", QUICK);
    if !can_push_input() {
        r.expect("Authenticated by chatty. Press Enter to continue.", QUICK);
        r.type_("\n");
    }
    assert_eq!(r.result(QUICK), PAM_SUCCESS, "{}", r.out);
}

#[test]
fn cancelling_the_prompt_aborts_every_method() {
    for reader in READERS {
        let mut r = Race::start_reading("cancel", &[finger("finger", 30, 0), password()], reader);
        r.expect("Password: ", QUICK);
        r.type_("\x04"); // ^D on an empty line: EOF, which the host treats as cancel
        assert_eq!(r.result(QUICK), PAM_CONV_ERR, "{reader}: {}", r.out);
    }
}

#[test]
fn all_methods_failing_reports_failure_and_every_message() {
    let mut r = Race::start("all-fail", &[finger("left", 0, 1), finger("right", 0, 1)]);
    let rc = r.result(QUICK);
    assert_ne!(rc, PAM_SUCCESS, "{}", r.out);
    assert!(
        r.out.contains("left: place your finger") && r.out.contains("right: place your finger"),
        "{}",
        r.out
    );
}

#[test]
fn messages_queued_behind_a_prompt_are_dropped_after_a_win() {
    // "chatty" speaks again while the password prompt blocks the host; by the
    // time the prompt is released, "finger" has won and that line is stale.
    let chatty = (
        "chatty".to_string(),
        "#!/bin/sh\necho 'chatty: hello'\n/usr/bin/sleep 0.5\necho 'chatty: stale'\nexec /usr/bin/sleep 30\n".to_string(),
    );
    let mut r = Race::start("stale", &[chatty, finger("finger", 2, 0), password()]);
    r.expect("Password: ", QUICK);
    if !can_push_input() {
        r.expect("Press Enter to continue.", QUICK);
        r.type_("\n");
    }
    assert_eq!(r.result(QUICK), PAM_SUCCESS, "{}", r.out);
    assert!(r.out.contains("chatty: hello"), "{}", r.out);
    assert!(!r.out.contains("chatty: stale"), "{}", r.out);
}

// ------------------------------------------------------- injected failures

/// A stand-in that leaves a mark if it ever runs.
fn marker() -> (String, String) {
    (
        "marker".into(),
        "#!/bin/sh\ntouch \"$(dirname \"$0\")/ran\"\n".into(),
    )
}

#[test]
fn a_failing_isolation_step_keeps_the_helper_from_running() {
    for syscall in ["setsid", "close_range"] {
        let mut r = Race::start_denying(&format!("deny-{syscall}"), &[marker()], syscall);
        assert_eq!(r.result(QUICK), PAM_SYSTEM_ERR, "{syscall}: {}", r.out);
        assert!(!r.dir.join("ran").exists(), "{syscall}: the helper ran");
    }
}

#[test]
fn a_setup_that_cannot_be_sent_leaves_no_process_behind() {
    // `result` checks that the host has no children left, zombies included.
    let mut r = Race::start_denying("deny-setup", &[marker()], "sendto");
    assert_eq!(r.result(QUICK), PAM_SYSTEM_ERR, "{}", r.out);
}

#[test]
fn a_reply_that_cannot_be_sent_ends_the_race_instead_of_hanging() {
    // Only the 14-byte reply carrying "hunter2" fails: tag, count, and one
    // present answer (flag, u32 length, 7 bytes).
    let mut r = Race::start_denying(
        "deny-reply",
        &[finger("finger", 30, 0), password()],
        "sendto:14",
    );
    r.expect("Password: ", QUICK);
    r.type_("hunter2\n");
    assert_eq!(r.result(QUICK), PAM_SYSTEM_ERR, "{}", r.out);
}

#[test]
fn clone3_refused_by_a_seccomp_filter_falls_back_to_clone() {
    // As container runtimes do: ENOSYS, so that callers fall back.
    let mut r = Race::start_denying("deny-clone3", &[finger("finger", 0, 0)], "clone3/ENOSYS");
    assert_eq!(r.result(QUICK), PAM_SUCCESS, "{}", r.out);
}
