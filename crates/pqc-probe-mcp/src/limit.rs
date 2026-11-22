//! A small probe budget for agent callers.
//!
//! An agent can call a tool in a loop far faster than a person clicks a button, and every probe
//! is real traffic to someone else's server. Two limits: at most `max_running` probes at once,
//! and at most `per_minute` probes started in any rolling 60-second window.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::{Semaphore, SemaphorePermit};

const WINDOW: Duration = Duration::from_secs(60);

pub struct Limiter {
    per_minute: usize,
    started: Mutex<VecDeque<Instant>>,
    running: Semaphore,
}

impl Limiter {
    pub fn new(per_minute: usize, max_running: usize) -> Self {
        Self {
            per_minute,
            started: Mutex::new(VecDeque::new()),
            running: Semaphore::new(max_running.max(1)),
        }
    }

    pub fn per_minute(&self) -> usize {
        self.per_minute
    }

    /// Take a slot now or say why not. Never waits: an agent should hear "slow down" rather than
    /// sit on a call that may outlive its client's timeout.
    pub fn try_start(&self) -> Result<SemaphorePermit<'_>, String> {
        self.try_start_at(Instant::now())
    }

    fn try_start_at(&self, now: Instant) -> Result<SemaphorePermit<'_>, String> {
        let permit = self.running.try_acquire().map_err(|_| {
            "another probe is still running; wait for it to finish before starting a new one"
                .to_string()
        })?;
        let mut started = self.started.lock().expect("limiter lock");
        while started
            .front()
            .is_some_and(|t| now.duration_since(*t) >= WINDOW)
        {
            started.pop_front();
        }
        if started.len() >= self.per_minute {
            let oldest = *started.front().expect("non-empty when at the limit");
            let wait = WINDOW.saturating_sub(now.duration_since(oldest)).as_secs() + 1;
            return Err(format!(
                "probe budget used up ({} probes per minute); try again in about {wait} s",
                self.per_minute
            ));
        }
        started.push_back(now);
        Ok(permit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_past_the_per_minute_budget_then_recovers() {
        let l = Limiter::new(2, 5);
        let t0 = Instant::now();
        drop(l.try_start_at(t0).unwrap());
        drop(l.try_start_at(t0).unwrap());
        let err = l.try_start_at(t0).unwrap_err();
        assert!(err.contains("2 probes per minute"), "{err}");
        assert!(l.try_start_at(t0 + WINDOW).is_ok());
    }

    #[test]
    fn refuses_a_second_concurrent_probe() {
        let l = Limiter::new(10, 1);
        let _held = l.try_start().unwrap();
        let err = l.try_start().unwrap_err();
        assert!(err.contains("still running"), "{err}");
    }
}
