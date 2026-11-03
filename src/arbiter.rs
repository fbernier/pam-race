//! The race rules, as a pure state machine (no I/O, no clock, no threads).
//!
//! The shell feeds it what happened (a helper spoke or finished, a prompt
//! returned) and asks it what the host thread should do next.
//!
//! * The first helper to succeed wins.
//! * A helper that fails after the user answered one of its prompts ends the
//!   race with its error: the user committed to that method (typed a wrong
//!   password) and expects the application's retry logic, not silence while
//!   other methods keep waiting.
//! * Otherwise the race fails once every helper has failed, with their common
//!   error if they agree and PAM_AUTH_ERR if not.
//! * A host conversation error on a prompt (^C, EOF, `sudo -n`, a cancelled
//!   dialog) cancels the race with that error.
//! * Prompts are held back until every helper has spoken or the settle
//!   deadline passes, so a hint like "Place your finger on the reader" is
//!   shown before a password prompt blocks the conversation. Informational
//!   messages always go ahead of queued prompts: they do not block.
//! * Once the user has answered a prompt, only that helper's messages are
//!   shown: the user is in its flow, and e.g. a fingerprint hint queued
//!   behind the password prompt would only be noise.
//! * Once decided, only the decider's informational messages are delivered
//!   (everyone's if all failed, nobody's after a win or a cancel).
//! * A helper with [`MAX_QUEUED`] conversation calls waiting for the host
//!   has its further informational messages dropped. Helpers do not wait for
//!   those to be shown, so this bounds memory; reading on keeps every helper
//!   heard, a win behind a flood of messages included. Prompts are never
//!   dropped, and a helper has at most one queued: it waits for the answer.
//! * A prompt the host is blocked in becomes obsolete once the race is
//!   decided or the helper that asked is gone. Its answer is then discarded,
//!   never committed to, and the prompt is released (see [`Release`]).
//!
//! Releasing a prompt means pushing a newline into the terminal, which
//! whatever process reads it takes as Enter. So a newline is only pushed
//! while the host is in the terminal's foreground (a background host is not
//! the reader; a shell may well be) and no complete line is queued, at most
//! once per [`RELEASE_BACKOFF`] step. After the last step the release gives
//! up: a newline of ours still unread is flushed and, if the host owns the
//! terminal, the user is asked to press Enter.

use std::collections::VecDeque;
use std::mem;
use std::time::{Duration, Instant};

use crate::types::{HelperId, Messages, PamError, PamResult, Responses, TtyState};

/// Conversation calls one helper may have waiting for the host.
pub const MAX_QUEUED: usize = 16;

/// Pause after each attempt to release a prompt, ~1.3 s in total. A newline
/// pushed before the host has set up the terminal is discarded by its
/// TCSAFLUSH, hence the retries; the first gap is long enough for a released
/// host to get back out of its conversation function, since a second newline
/// arriving after it restored echo would show up as a blank line.
pub const RELEASE_BACKOFF: [Duration; 6] = [
    Duration::from_millis(50),
    Duration::from_millis(100),
    Duration::from_millis(150),
    Duration::from_millis(250),
    Duration::from_millis(350),
    Duration::from_millis(400),
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    Won(HelperId),
    Lost {
        error: PamError,
        decider: Option<HelperId>,
    },
    Cancelled(PamError),
}

impl Outcome {
    pub fn result(self) -> PamResult {
        match self {
            Outcome::Won(_) => Ok(()),
            Outcome::Lost { error, .. } | Outcome::Cancelled(error) => Err(error),
        }
    }

    fn delivers(self, from: HelperId, msgs: &Messages) -> bool {
        !msgs.is_prompt()
            && match self {
                Outcome::Won(_) | Outcome::Cancelled(_) => false,
                Outcome::Lost { decider, .. } => decider.is_none_or(|d| d == from),
            }
    }
}

/// What the host thread must do next.
#[derive(Debug)]
pub enum HostStep {
    /// Pass informational messages to the host conversation.
    Show(HelperId, Messages),
    /// Pass a prompt to the host conversation, then report via
    /// [`Arbiter::prompt_returned`].
    Ask(HelperId, Messages),
    /// Wait for news; at the latest until the given instant.
    Wait(Option<Instant>),
    /// Return this from pam_sm_authenticate.
    Finish(PamResult),
}

/// What to do with an answered prompt.
#[derive(Debug)]
pub enum AfterPrompt {
    Reply(HelperId, Responses),
    /// Nobody needs the answer (the race is over, or the helper that asked
    /// is gone); it is dropped unread.
    Discard,
}

#[derive(Debug)]
pub struct PromptReturn {
    pub action: AfterPrompt,
    /// A newline was pushed into the terminal during this prompt; any of it
    /// left unread must be flushed before anything else reads the terminal.
    pub flush_input: bool,
}

/// Why the prompt the host is blocked in is no longer needed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Obsolete {
    Decided(Outcome),
    /// The helper that asked is gone; the race goes on.
    HelperGone(HelperId),
}

/// What the watcher must do about the host's prompt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Release {
    /// Nothing for now: step again at the given instant, or (`None`) once
    /// something has changed.
    Idle(Option<Instant>),
    /// Push a newline into the terminal, report how that went
    /// ([`Arbiter::newline_pushed`], [`Arbiter::push_failed`]) and step again.
    Push,
    /// Stop trying. Flush the terminal's input first if `flush` (a newline of
    /// ours may still be unread); with a `notice`, ask the user to press Enter.
    GiveUp {
        flush: bool,
        notice: Option<Obsolete>,
    },
}

/// Progress of the release of the current prompt.
#[derive(Clone, Copy, Default)]
enum Releasing {
    #[default]
    NotStarted,
    /// `attempts` steps of [`RELEASE_BACKOFF`] taken; the next one is due at
    /// `next`.
    Trying { attempts: usize, next: Instant },
    /// Pushing is impossible: give up at the next step.
    Failed,
    /// Given up; the prompt is the user's to end.
    GaveUp,
}

#[derive(Default)]
struct Helper {
    heard: bool,
    finished: Option<PamResult>,
}

pub struct Arbiter {
    settle_until: Instant,
    helpers: Vec<Helper>,
    queue: VecDeque<(HelperId, Messages)>,
    prompting: Option<HelperId>,
    /// The helper whose prompt the user answered. At most one: once set,
    /// nobody else's prompts reach the user.
    committed: Option<HelperId>,
    releasing: Releasing,
    /// A newline of ours may be in the terminal's input queue.
    pushed: bool,
    outcome: Option<Outcome>,
}

impl Arbiter {
    pub fn new(helpers: usize, settle_until: Instant) -> Arbiter {
        assert!(helpers > 0, "a race needs at least one helper");
        Arbiter {
            settle_until,
            helpers: (0..helpers).map(|_| Helper::default()).collect(),
            queue: VecDeque::new(),
            prompting: None,
            committed: None,
            releasing: Releasing::NotStarted,
            pushed: false,
            outcome: None,
        }
    }

    pub fn outcome(&self) -> Option<Outcome> {
        self.outcome
    }

    pub fn helper_said(&mut self, from: HelperId, msgs: Messages) {
        self.helpers[from.0].heard = true;
        let delivers = match self.outcome {
            Some(o) => o.delivers(from, &msgs),
            None => self.committed.is_none_or(|c| c == from),
        };
        let room =
            msgs.is_prompt() || self.queue.iter().filter(|(f, _)| *f == from).count() < MAX_QUEUED;
        if delivers && room {
            self.queue.push_back((from, msgs));
        }
    }

    /// Returns the outcome if this decided the race. A helper finishes once:
    /// its first result stands.
    pub fn helper_finished(&mut self, who: HelperId, result: PamResult) -> Option<Outcome> {
        let h = &mut self.helpers[who.0];
        if h.finished.is_some() {
            return None;
        }
        h.heard = true;
        h.finished = Some(result);
        let committed = self.committed == Some(who);
        // Nobody is left to read the answer to its queued prompts.
        self.queue
            .retain(|(from, m)| *from != who || !m.is_prompt());
        if self.outcome.is_some() {
            return None;
        }
        let decided = match result {
            Ok(()) => Some(Outcome::Won(who)),
            Err(error) if committed => Some(Outcome::Lost {
                error,
                decider: Some(who),
            }),
            Err(_) => self.all_failed().map(|error| Outcome::Lost {
                error,
                decider: None,
            }),
        };
        if let Some(o) = decided {
            self.outcome = Some(o);
            self.queue.retain(|(from, m)| o.delivers(*from, m));
        }
        decided
    }

    fn all_failed(&self) -> Option<PamError> {
        let mut errors = self.helpers.iter().map(|h| h.finished?.err());
        let first = errors.next()??;
        errors.try_fold(first, |acc, e| {
            Some(if e? == acc { acc } else { PamError::AUTH_ERR })
        })
    }

    /// Nothing more will be heard from any helper: every unfinished one has
    /// failed with `error`. Returns the outcome if this decided the race.
    pub fn abandon(&mut self, error: PamError) -> Option<Outcome> {
        let unfinished: Vec<HelperId> = (0..self.helpers.len())
            .map(HelperId)
            .filter(|h| self.helpers[h.0].finished.is_none())
            .collect();
        unfinished
            .into_iter()
            .filter_map(|h| self.helper_finished(h, Err(error)))
            .last()
    }

    pub fn next_for_host(&mut self, now: Instant) -> HostStep {
        debug_assert!(
            self.prompting.is_none(),
            "host thread asked for work while prompting"
        );
        if let Some(o) = self.outcome {
            return match self.queue.pop_front() {
                Some((from, msgs)) => HostStep::Show(from, msgs),
                None => HostStep::Finish(o.result()),
            };
        }
        let settled = now >= self.settle_until || self.helpers.iter().all(|h| h.heard);
        let next = self.queue.iter().position(|(_, m)| !m.is_prompt());
        // Only prompts are left if `next` is None; they go in arrival order.
        match next.or_else(|| (settled && !self.queue.is_empty()).then_some(0)) {
            Some(i) => {
                let (from, msgs) = self.queue.remove(i).expect("index from position");
                if msgs.is_prompt() {
                    self.prompting = Some(from);
                    HostStep::Ask(from, msgs)
                } else {
                    HostStep::Show(from, msgs)
                }
            }
            None => HostStep::Wait((!self.queue.is_empty()).then_some(self.settle_until)),
        }
    }

    pub fn prompt_returned(
        &mut self,
        from: HelperId,
        answer: Result<Responses, PamError>,
    ) -> PromptReturn {
        debug_assert_eq!(self.prompting, Some(from));
        self.prompting = None;
        self.releasing = Releasing::NotStarted;
        let flush_input = mem::take(&mut self.pushed);
        let gone = self.helpers[from.0].finished.is_some();
        let action = match (self.outcome, answer) {
            (Some(_), _) => AfterPrompt::Discard,
            (None, Err(e)) => {
                self.outcome = Some(Outcome::Cancelled(e));
                self.queue.clear();
                AfterPrompt::Discard
            }
            // Nobody is left to read it, and nothing to commit to: the other
            // helpers stay in the race.
            (None, Ok(_)) if gone => AfterPrompt::Discard,
            (None, Ok(r)) => {
                self.committed = Some(from);
                self.queue.retain(|(f, _)| *f == from);
                AfterPrompt::Reply(from, r)
            }
        };
        PromptReturn {
            action,
            flush_input,
        }
    }

    /// The next step in releasing the host's prompt, given the terminal as
    /// seen at `now`. See the module documentation for the rules.
    pub fn release_step(&mut self, now: Instant, tty: TtyState) -> Release {
        let Some(why) = self.obsolete() else {
            return Release::Idle(None);
        };
        let attempts = match self.releasing {
            Releasing::GaveUp => return Release::Idle(None),
            Releasing::NotStarted => 0,
            Releasing::Trying { next, .. } if now < next => return Release::Idle(Some(next)),
            Releasing::Trying { attempts, .. } => attempts,
            Releasing::Failed => RELEASE_BACKOFF.len(),
        };
        let Some(pause) = RELEASE_BACKOFF.get(attempts) else {
            self.releasing = Releasing::GaveUp;
            return Release::GiveUp {
                flush: mem::take(&mut self.pushed),
                notice: (tty != TtyState::Background).then_some(why),
            };
        };
        let next = now + *pause;
        self.releasing = Releasing::Trying {
            attempts: attempts + 1,
            next,
        };
        match tty {
            TtyState::Idle => Release::Push,
            TtyState::Background | TtyState::LineQueued => Release::Idle(Some(next)),
        }
    }

    /// The [`Release::Push`] went through.
    pub fn newline_pushed(&mut self) {
        self.pushed = true;
    }

    /// The [`Release::Push`] failed (no TIOCSTI): pushing will not work.
    pub fn push_failed(&mut self) {
        self.releasing = Releasing::Failed;
    }

    fn obsolete(&self) -> Option<Obsolete> {
        let asking = self.prompting?;
        match self.outcome {
            Some(o) => Some(Obsolete::Decided(o)),
            None => self.helpers[asking.0]
                .finished
                .is_some()
                .then_some(Obsolete::HelperGone(asking)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::types::{Message, Secret, Style, Text};

    const A: HelperId = HelperId(0);
    const B: HelperId = HelperId(1);
    const C: HelperId = HelperId(2);

    fn info(s: &str) -> Messages {
        Messages::parse(vec![Message {
            style: Style::TextInfo,
            text: Text::parse(s.as_bytes()).unwrap(),
        }])
        .unwrap()
    }

    fn prompt() -> Messages {
        Messages::parse(vec![Message {
            style: Style::PromptEchoOff,
            text: Text::parse(b"Password: ").unwrap(),
        }])
        .unwrap()
    }

    fn answer(to: &Messages) -> Result<Responses, PamError> {
        Ok(Responses::parse(vec![Some(Secret::new(b"pw".to_vec()))], to).unwrap())
    }

    struct T {
        arb: Arbiter,
        t0: Instant,
        /// A step `shown()` pulled that changed state (an Ask) and must not
        /// be lost; recomputable steps are simply dropped.
        peeked: Option<HostStep>,
    }

    impl T {
        fn new(n: usize) -> T {
            let t0 = Instant::now();
            T {
                arb: Arbiter::new(n, t0 + Duration::from_millis(250)),
                t0,
                peeked: None,
            }
        }
        fn step(&mut self) -> HostStep {
            self.peeked
                .take()
                .unwrap_or_else(|| self.arb.next_for_host(self.t0))
        }
        fn step_late(&mut self) -> HostStep {
            self.peeked
                .take()
                .unwrap_or_else(|| self.arb.next_for_host(self.t0 + Duration::from_secs(1)))
        }
        /// Messages shown up to the next non-Show step.
        fn shown(&mut self) -> Vec<(HelperId, String)> {
            let mut out = Vec::new();
            loop {
                match self.step() {
                    HostStep::Show(h, m) => out.push((
                        h,
                        m.as_slice()[0]
                            .text
                            .as_cstr()
                            .to_string_lossy()
                            .into_owned(),
                    )),
                    ask @ HostStep::Ask(..) => {
                        self.peeked = Some(ask);
                        return out;
                    }
                    _ => return out,
                }
            }
        }
        /// Answer the pending prompt from `who`.
        fn ask_and_answer(&mut self, who: HelperId) {
            let HostStep::Ask(h, m) = self.step() else {
                panic!("expected a prompt")
            };
            assert_eq!(h, who);
            let r = self.arb.prompt_returned(h, answer(&m));
            assert!(matches!(r.action, AfterPrompt::Reply(h, _) if h == who));
        }
    }

    #[test]
    fn first_success_wins_while_others_are_pending() {
        let mut t = T::new(3);
        assert_eq!(t.arb.helper_finished(B, Err(PamError::AUTH_ERR)), None);
        assert_eq!(t.arb.helper_finished(C, Ok(())), Some(Outcome::Won(C)));
        assert_eq!(
            t.arb.helper_finished(A, Ok(())),
            None,
            "the race is decided once"
        );
        assert!(matches!(t.step(), HostStep::Finish(Ok(()))));
    }

    #[test]
    fn failing_after_the_user_answered_ends_the_race() {
        let mut t = T::new(2);
        t.arb.helper_said(A, info("place finger"));
        t.arb.helper_said(B, prompt());
        assert_eq!(t.shown(), [(A, "place finger".into())]);
        t.ask_and_answer(B);
        let lost = Outcome::Lost {
            error: PamError::AUTH_ERR,
            decider: Some(B),
        };
        assert_eq!(
            t.arb.helper_finished(B, Err(PamError::AUTH_ERR)),
            Some(lost)
        );
        assert!(matches!(
            t.step(),
            HostStep::Finish(Err(PamError::AUTH_ERR))
        ));
    }

    #[test]
    fn failing_without_user_input_lets_the_others_continue() {
        let mut t = T::new(2);
        t.arb.helper_said(B, prompt());
        assert_eq!(t.arb.helper_finished(A, Err(PamError::AUTH_ERR)), None);
        t.ask_and_answer(B);
        assert_eq!(t.arb.helper_finished(B, Ok(())), Some(Outcome::Won(B)));
    }

    #[test]
    fn when_everyone_fails_the_common_error_or_auth_err_is_returned() {
        let mut same = T::new(2);
        same.arb.helper_finished(A, Err(PamError::SYSTEM_ERR));
        let o = same.arb.helper_finished(B, Err(PamError::SYSTEM_ERR));
        assert_eq!(
            o,
            Some(Outcome::Lost {
                error: PamError::SYSTEM_ERR,
                decider: None
            })
        );

        let mut mixed = T::new(2);
        mixed.arb.helper_finished(A, Err(PamError::SYSTEM_ERR));
        let o = mixed.arb.helper_finished(B, Err(PamError::CONV_ERR));
        assert_eq!(
            o,
            Some(Outcome::Lost {
                error: PamError::AUTH_ERR,
                decider: None
            })
        );
    }

    #[test]
    fn when_everyone_fails_everyones_messages_are_shown() {
        let mut t = T::new(2);
        t.arb.helper_said(A, info("a: no reader"));
        t.arb.helper_said(B, info("b: no key"));
        t.arb.helper_finished(A, Err(PamError::AUTH_ERR));
        t.arb.helper_finished(B, Err(PamError::AUTH_ERR));
        assert_eq!(
            t.shown(),
            [(A, "a: no reader".into()), (B, "b: no key".into())]
        );
        assert!(matches!(t.step(), HostStep::Finish(Err(_))));
    }

    #[test]
    fn prompts_wait_for_every_helper_or_the_deadline_but_messages_do_not() {
        let mut t = T::new(2);
        t.arb.helper_said(B, prompt());
        assert!(
            matches!(t.step(), HostStep::Wait(Some(_))),
            "A has not spoken yet"
        );
        assert!(
            matches!(t.step_late(), HostStep::Ask(B, _)),
            "deadline passed"
        );

        let mut t = T::new(2);
        t.arb.helper_said(B, prompt());
        t.arb.helper_said(A, info("place finger"));
        assert_eq!(
            t.shown(),
            [(A, "place finger".into())],
            "message overtakes the held prompt"
        );
        assert!(
            matches!(t.step(), HostStep::Ask(B, _)),
            "everyone has spoken"
        );
    }

    #[test]
    fn nothing_queued_means_wait_without_deadline() {
        let mut t = T::new(2);
        assert!(matches!(t.step(), HostStep::Wait(None)));
    }

    #[test]
    fn after_a_win_queued_messages_and_prompts_are_dropped() {
        let mut t = T::new(3);
        t.arb.helper_said(A, info("a: stale"));
        t.arb.helper_said(B, prompt());
        t.arb.helper_finished(C, Ok(()));
        t.arb.helper_said(A, info("a: later"));
        assert!(matches!(t.step(), HostStep::Finish(Ok(()))));
    }

    #[test]
    fn after_a_committed_failure_only_the_deciders_messages_are_shown() {
        let mut t = T::new(2);
        t.arb.helper_said(A, info("place finger"));
        t.arb.helper_said(B, prompt());
        t.shown();
        t.ask_and_answer(B);
        t.arb.helper_said(A, info("a: stale"));
        t.arb.helper_said(B, info("b: account locked"));
        t.arb.helper_finished(B, Err(PamError::AUTH_ERR));
        assert_eq!(t.shown(), [(B, "b: account locked".into())]);
    }

    #[test]
    fn answering_a_prompt_silences_the_other_helpers() {
        // Seen with a slow fingerprint reader: its hint arrives after the
        // settle deadline, while the password prompt is already up.
        let mut t = T::new(2);
        t.arb.helper_said(B, prompt());
        let HostStep::Ask(h, m) = t.step_late() else {
            panic!("expected the prompt after the deadline")
        };
        t.arb.helper_said(A, info("place finger"));
        assert!(matches!(
            t.arb.prompt_returned(h, answer(&m)).action,
            AfterPrompt::Reply(..)
        ));
        t.arb.helper_said(A, info("finger not recognised"));
        t.arb.helper_said(B, info("b: checking"));
        assert_eq!(t.shown(), [(B, "b: checking".into())]);
        assert_eq!(
            t.arb.outcome(),
            None,
            "silenced, not decided: the fingerprint can still win"
        );
    }

    #[test]
    fn host_conversation_error_cancels_the_race() {
        let mut t = T::new(2);
        t.arb.helper_said(A, info("place finger"));
        t.arb.helper_said(B, prompt());
        t.shown();
        let HostStep::Ask(h, _) = t.step() else {
            panic!()
        };
        t.arb.helper_said(A, info("a: retry"));
        let r = t.arb.prompt_returned(h, Err(PamError::CONV_ERR));
        assert!(matches!(r.action, AfterPrompt::Discard));
        assert_eq!(
            t.arb.outcome(),
            Some(Outcome::Cancelled(PamError::CONV_ERR))
        );
        assert!(matches!(
            t.step(),
            HostStep::Finish(Err(PamError::CONV_ERR))
        ));
        assert_eq!(t.arb.helper_finished(A, Ok(())), None, "too late to win");
    }

    /// B's prompt is up and A has just won.
    fn won_while_prompting() -> (T, HelperId, Messages) {
        let mut t = T::new(2);
        t.arb.helper_said(A, info("place finger"));
        t.arb.helper_said(B, prompt());
        t.shown();
        let HostStep::Ask(h, m) = t.step() else {
            panic!()
        };
        assert_eq!(t.arb.helper_finished(A, Ok(())), Some(Outcome::Won(A)));
        (t, h, m)
    }

    #[test]
    fn answer_to_a_prompt_outlived_by_the_race_is_discarded_and_input_flushed() {
        let (mut t, h, m) = won_while_prompting();
        assert_eq!(t.arb.release_step(t.t0, TtyState::Idle), Release::Push);
        t.arb.newline_pushed();
        let r = t.arb.prompt_returned(h, answer(&m));
        assert!(matches!(r.action, AfterPrompt::Discard));
        assert!(r.flush_input);
        assert!(matches!(t.step(), HostStep::Finish(Ok(()))));
    }

    #[test]
    fn a_release_pushes_only_into_an_idle_terminal_then_gives_up() {
        let (mut t, ..) = won_while_prompting();
        let mut now = t.t0;
        let mut pushes = 0;
        // Idle, then a line is queued (ours, unread), then idle again...
        for (i, tty) in [TtyState::Idle, TtyState::LineQueued]
            .into_iter()
            .cycle()
            .take(RELEASE_BACKOFF.len())
            .enumerate()
        {
            match t.arb.release_step(now, tty) {
                Release::Push => {
                    pushes += 1;
                    t.arb.newline_pushed();
                }
                Release::Idle(Some(_)) => assert_eq!(tty, TtyState::LineQueued),
                other => panic!("step {i}: {other:?}"),
            }
            let next = now + RELEASE_BACKOFF[i];
            assert_eq!(
                t.arb.release_step(now, TtyState::Idle),
                Release::Idle(Some(next)),
                "not before the pause is over"
            );
            now = next;
        }
        assert_eq!(pushes, RELEASE_BACKOFF.len() / 2);
        assert_eq!(
            t.arb.release_step(now, TtyState::LineQueued),
            Release::GiveUp {
                flush: true,
                notice: Some(Obsolete::Decided(Outcome::Won(A)))
            }
        );
        assert_eq!(t.arb.release_step(now, TtyState::Idle), Release::Idle(None));
    }

    #[test]
    fn a_background_host_never_pushes_and_gets_no_notice() {
        let (mut t, ..) = won_while_prompting();
        let mut now = t.t0;
        for pause in RELEASE_BACKOFF {
            assert!(matches!(
                t.arb.release_step(now, TtyState::Background),
                Release::Idle(Some(_))
            ));
            now += pause;
        }
        assert_eq!(
            t.arb.release_step(now, TtyState::Background),
            Release::GiveUp {
                flush: false,
                notice: None
            }
        );
    }

    #[test]
    fn a_failed_push_gives_up_at_once_with_a_notice() {
        let (mut t, ..) = won_while_prompting();
        assert_eq!(t.arb.release_step(t.t0, TtyState::Idle), Release::Push);
        t.arb.push_failed();
        assert_eq!(
            t.arb.release_step(t.t0, TtyState::Idle),
            Release::GiveUp {
                flush: false,
                notice: Some(Obsolete::Decided(Outcome::Won(A)))
            }
        );
    }

    #[test]
    fn a_prompt_still_needed_is_not_released() {
        let mut t = T::new(2);
        t.arb.helper_said(B, prompt());
        let HostStep::Ask(..) = t.step_late() else {
            panic!()
        };
        assert_eq!(
            t.arb.release_step(t.t0, TtyState::Idle),
            Release::Idle(None)
        );
    }

    #[test]
    fn a_prompt_whose_helper_died_is_released_and_its_answer_dropped() {
        let mut t = T::new(2);
        t.arb.helper_said(B, prompt());
        t.arb.helper_said(A, prompt());
        let HostStep::Ask(h, m) = t.step() else {
            panic!()
        };
        assert_eq!(h, B);
        assert_eq!(t.arb.helper_finished(B, Err(PamError::SYSTEM_ERR)), None);
        assert_eq!(t.arb.release_step(t.t0, TtyState::Idle), Release::Push);
        t.arb.newline_pushed();
        let r = t.arb.prompt_returned(h, answer(&m));
        assert!(matches!(r.action, AfterPrompt::Discard), "B is gone");
        assert!(r.flush_input);
        assert!(
            matches!(t.step(), HostStep::Ask(A, _)),
            "not committed to B: A's prompt is still asked"
        );
    }

    #[test]
    fn a_helper_finishes_once() {
        let mut t = T::new(2);
        assert_eq!(t.arb.helper_finished(B, Err(PamError::AUTH_ERR)), None);
        // E.g. a reply that could not be sent to the already finished B.
        assert_eq!(t.arb.helper_finished(B, Err(PamError::SYSTEM_ERR)), None);
        assert_eq!(
            t.arb.helper_finished(A, Err(PamError::AUTH_ERR)),
            Some(Outcome::Lost {
                error: PamError::AUTH_ERR,
                decider: None
            }),
            "B's first result stands"
        );
    }

    #[test]
    fn prompts_from_a_helper_that_died_are_not_asked() {
        let mut t = T::new(2);
        t.arb.helper_said(A, prompt());
        t.arb.helper_said(B, info("place finger"));
        t.arb.helper_finished(A, Err(PamError::SYSTEM_ERR));
        t.shown();
        assert!(matches!(t.step_late(), HostStep::Wait(None)));
    }

    #[test]
    fn messages_beyond_a_helpers_backlog_are_dropped_but_prompts_never() {
        let mut t = T::new(2);
        for i in 0..MAX_QUEUED + 5 {
            t.arb.helper_said(A, info(&format!("a{i}")));
        }
        t.arb.helper_said(B, info("b0"));
        t.arb.helper_said(A, prompt());
        let expected: Vec<(HelperId, String)> = (0..MAX_QUEUED)
            .map(|i| (A, format!("a{i}")))
            .chain([(B, "b0".into())])
            .collect();
        assert_eq!(t.shown(), expected, "the first ones, per helper");
        assert!(matches!(t.step(), HostStep::Ask(A, _)));
    }

    #[test]
    fn abandoning_fails_every_unfinished_helper() {
        let mut t = T::new(3);
        t.arb.helper_finished(A, Err(PamError::AUTH_ERR));
        assert_eq!(
            t.arb.abandon(PamError::SYSTEM_ERR),
            Some(Outcome::Lost {
                error: PamError::AUTH_ERR,
                decider: None
            }),
            "A's own error disagrees with the rest"
        );

        let mut t = T::new(2);
        t.arb.helper_finished(A, Ok(()));
        assert_eq!(t.arb.abandon(PamError::SYSTEM_ERR), None, "already won");
        assert!(matches!(t.step(), HostStep::Finish(Ok(()))));
    }
}
