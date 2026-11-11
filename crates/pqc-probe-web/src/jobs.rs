//! In-memory job store: ids, status, concurrency cap, deadline, expiry.
//!
//! Locking: one `std::sync::Mutex` around a map, held only for short non-async sections and
//! never across an `.await`. Probes run in their own task, so a panic inside a prober marks the
//! job failed instead of leaving it "running" forever, and a timed-out probe is aborted (which
//! kills any child process through `kill_on_drop`).

use crate::config::Config;
use crate::model::{JobStatus, JobView};
use crate::prober::{ProbeJob, Prober};
use pqc_probe_core::report::rfc3339_utc;
use pqc_probe_core::Report;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;

/// Anything that must live exactly as long as the job (for example a client's in-flight slot).
pub type Hold = Box<dyn Send + 'static>;

/// Outcome of [`JobStore::submit_keyed`].
#[derive(Debug, PartialEq, Eq)]
pub enum Submitted {
    New(String),
    /// A job for the same key started within the cooldown; nothing new was queued.
    Reused(String),
}

#[derive(Debug)]
pub enum SubmitError {
    /// Too many jobs queued or running.
    Busy,
}

/// What `GET .../report` should say.
#[derive(Debug)]
pub enum ReportLookup {
    NotFound,
    /// Still queued or running.
    NotReady(JobStatus),
    /// Finished without a report.
    Unavailable {
        status: JobStatus,
        error: Option<String>,
    },
    Ready(Arc<Report>),
}

struct JobRecord {
    input: String,
    status: JobStatus,
    created_at: String,
    finished_at: Option<String>,
    finished: Option<Instant>,
    error: Option<String>,
    report: Option<Arc<Report>>,
}

pub struct JobStore {
    jobs: Mutex<HashMap<String, JobRecord>>,
    semaphore: Arc<Semaphore>,
    queue_limit: usize,
    job_timeout: Duration,
    result_ttl: Duration,
    /// Most recent job per request key, for the per-target cooldown.
    recent: Mutex<HashMap<String, (String, Instant)>>,
    cooldown: Duration,
}

fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    rfc3339_utc(secs)
}

/// 128 bits of randomness minus the UUID version bits (122 random bits), as 32 hex characters.
fn new_job_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

impl JobStore {
    pub fn new(config: &Config) -> Arc<Self> {
        Arc::new(Self {
            jobs: Mutex::new(HashMap::new()),
            semaphore: Arc::new(Semaphore::new(config.max_concurrent.max(1))),
            queue_limit: config.queue_limit.max(1),
            job_timeout: config.job_timeout,
            result_ttl: config.result_ttl,
            recent: Mutex::new(HashMap::new()),
            cooldown: config.limits.target_cooldown,
        })
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, JobRecord>> {
        self.jobs.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Jobs that are queued or running.
    pub fn active(&self) -> usize {
        self.lock()
            .values()
            .filter(|j| !j.status.is_finished())
            .count()
    }

    pub fn queue_limit(&self) -> usize {
        self.queue_limit
    }

    /// Queue a job. Fails fast with [`SubmitError::Busy`] when the queue is full.
    pub fn submit(
        self: &Arc<Self>,
        job: ProbeJob,
        prober: Arc<dyn Prober>,
    ) -> Result<String, SubmitError> {
        self.submit_with(job, prober, Box::new(()))
    }

    /// The job a request with this `key` would be answered with: one that started within the
    /// cooldown and has not been swept yet.
    pub fn recent(&self, key: &str) -> Option<String> {
        let recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        self.fresh(&recent, key)
    }

    // Lock order is always `recent` then `jobs`, never the other way round.
    fn fresh(&self, recent: &HashMap<String, (String, Instant)>, key: &str) -> Option<String> {
        let (id, at) = recent.get(key)?;
        (at.elapsed() < self.cooldown && self.lock().contains_key(id)).then(|| id.clone())
    }

    /// Like [`submit`](Self::submit), but a request whose `key` already started a job within the
    /// cooldown gets that job back and nothing new is queued. `hold` is dropped when the job
    /// ends (or at once when the earlier job is reused).
    pub fn submit_keyed(
        self: &Arc<Self>,
        key: String,
        job: ProbeJob,
        prober: Arc<dyn Prober>,
        hold: Hold,
    ) -> Result<Submitted, SubmitError> {
        let mut recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(id) = self.fresh(&recent, &key) {
            return Ok(Submitted::Reused(id));
        }
        let id = self.submit_with(job, prober, hold)?;
        recent.insert(key, (id.clone(), Instant::now()));
        Ok(Submitted::New(id))
    }

    fn submit_with(
        self: &Arc<Self>,
        job: ProbeJob,
        prober: Arc<dyn Prober>,
        hold: Hold,
    ) -> Result<String, SubmitError> {
        let id = new_job_id();
        {
            let mut jobs = self.lock();
            let active = jobs.values().filter(|j| !j.status.is_finished()).count();
            if active >= self.queue_limit {
                return Err(SubmitError::Busy);
            }
            jobs.insert(
                id.clone(),
                JobRecord {
                    input: job.request.target.clone(),
                    status: JobStatus::Queued,
                    created_at: now_rfc3339(),
                    finished_at: None,
                    finished: None,
                    error: None,
                    report: None,
                },
            );
        }
        let store = Arc::clone(self);
        let task_id = id.clone();
        tokio::spawn(async move {
            let _hold = hold;
            store.run(task_id, job, prober).await
        });
        Ok(id)
    }

    async fn run(self: Arc<Self>, id: String, job: ProbeJob, prober: Arc<dyn Prober>) {
        let permit = match Arc::clone(&self.semaphore).acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                self.finish(
                    &id,
                    JobStatus::Failed,
                    Some("service is shutting down".into()),
                    None,
                );
                return;
            }
        };
        self.set_status(&id, JobStatus::Running);

        // The probe runs in its own task: a panic becomes a JoinError instead of killing this
        // one, and `abort()` on timeout drops the probe future (and with it any child process).
        let mut handle = tokio::spawn(async move { prober.probe(&job).await });
        let outcome = tokio::time::timeout(self.job_timeout, &mut handle).await;
        let (status, error, report) = match outcome {
            Ok(Ok(Ok(report))) => (JobStatus::Succeeded, None, Some(Arc::new(report))),
            Ok(Ok(Err(message))) => (JobStatus::Failed, Some(message), None),
            Ok(Err(join_error)) => {
                tracing::error!(job = %id, "probe task ended abnormally: {join_error}");
                (
                    JobStatus::Failed,
                    Some("internal error while probing".to_string()),
                    None,
                )
            }
            Err(_) => {
                handle.abort();
                (
                    JobStatus::TimedOut,
                    Some(format!(
                        "the probe did not finish within {} seconds",
                        self.job_timeout.as_secs()
                    )),
                    None,
                )
            }
        };
        drop(permit);
        self.finish(&id, status, error, report);
    }

    fn set_status(&self, id: &str, status: JobStatus) {
        if let Some(j) = self.lock().get_mut(id) {
            j.status = status;
        }
    }

    fn finish(
        &self,
        id: &str,
        status: JobStatus,
        error: Option<String>,
        report: Option<Arc<Report>>,
    ) {
        if let Some(j) = self.lock().get_mut(id) {
            j.status = status;
            j.error = error;
            j.report = report;
            j.finished = Some(Instant::now());
            j.finished_at = Some(now_rfc3339());
        }
    }

    pub fn view(&self, id: &str) -> Option<JobView> {
        self.lock().get(id).map(|j| JobView {
            id: id.to_string(),
            status: j.status,
            target: j.input.clone(),
            created_at: j.created_at.clone(),
            finished_at: j.finished_at.clone(),
            error: j.error.clone(),
            report_url: j
                .report
                .is_some()
                .then(|| format!("/api/v1/probes/{id}/report")),
        })
    }

    pub fn report(&self, id: &str) -> ReportLookup {
        match self.lock().get(id) {
            None => ReportLookup::NotFound,
            Some(j) if !j.status.is_finished() => ReportLookup::NotReady(j.status),
            Some(j) => match &j.report {
                Some(r) => ReportLookup::Ready(Arc::clone(r)),
                None => ReportLookup::Unavailable {
                    status: j.status,
                    error: j.error.clone(),
                },
            },
        }
    }

    /// Drop finished jobs older than the result TTL. Returns how many were removed.
    pub fn sweep(&self) -> usize {
        let ttl = self.result_ttl;
        let cooldown = self.cooldown;
        // Not nested with the jobs lock below (see the lock order note on `fresh`).
        self.recent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, (_, at)| at.elapsed() < cooldown);
        let mut jobs = self.lock();
        let before = jobs.len();
        jobs.retain(|_, j| match j.finished {
            Some(t) => t.elapsed() < ttl,
            None => true,
        });
        before - jobs.len()
    }

    /// Sweep once a minute for as long as the process runs.
    pub fn spawn_sweeper(self: &Arc<Self>) {
        let store = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                let removed = store.sweep();
                if removed > 0 {
                    tracing::debug!(removed, "swept finished jobs");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::is_valid_job_id;
    use crate::testing::{job, FakeProber};

    fn cfg(max_concurrent: usize, queue_limit: usize, timeout_ms: u64, ttl_ms: u64) -> Config {
        Config {
            max_concurrent,
            queue_limit,
            job_timeout: Duration::from_millis(timeout_ms),
            result_ttl: Duration::from_millis(ttl_ms),
            ..Config::default()
        }
    }

    async fn wait_finished(store: &JobStore, id: &str) -> JobView {
        for _ in 0..300 {
            let v = store.view(id).expect("job exists");
            if v.status.is_finished() {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("job {id} did not finish");
    }

    #[test]
    fn ids_are_32_hex_and_distinct() {
        let a = new_job_id();
        let b = new_job_id();
        assert!(is_valid_job_id(&a) && is_valid_job_id(&b));
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn a_job_runs_to_success_and_keeps_its_report() {
        let store = JobStore::new(&cfg(2, 10, 5_000, 60_000));
        let id = store.submit(job("example.test"), FakeProber::ok()).unwrap();
        let v = wait_finished(&store, &id).await;
        assert_eq!(v.status, JobStatus::Succeeded);
        assert!(v.finished_at.is_some() && v.error.is_none() && v.report_url.is_some());
        assert!(matches!(store.report(&id), ReportLookup::Ready(_)));
    }

    #[tokio::test]
    async fn a_failing_prober_fails_the_job_with_its_message() {
        let store = JobStore::new(&cfg(2, 10, 5_000, 60_000));
        let id = store
            .submit(job("example.test"), FakeProber::fails("boom"))
            .unwrap();
        let v = wait_finished(&store, &id).await;
        assert_eq!(v.status, JobStatus::Failed);
        assert_eq!(v.error.as_deref(), Some("boom"));
        assert!(matches!(
            store.report(&id),
            ReportLookup::Unavailable {
                status: JobStatus::Failed,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn a_panicking_prober_fails_the_job_instead_of_hanging_it() {
        let store = JobStore::new(&cfg(2, 10, 5_000, 60_000));
        let id = store
            .submit(job("example.test"), FakeProber::panics())
            .unwrap();
        let v = wait_finished(&store, &id).await;
        assert_eq!(v.status, JobStatus::Failed);
        assert_eq!(v.error.as_deref(), Some("internal error while probing"));
        assert_eq!(store.active(), 0);
    }

    #[tokio::test]
    async fn a_slow_prober_times_out() {
        let store = JobStore::new(&cfg(2, 10, 50, 60_000));
        let id = store
            .submit(
                job("example.test"),
                FakeProber::slow(Duration::from_secs(30)),
            )
            .unwrap();
        let v = wait_finished(&store, &id).await;
        assert_eq!(v.status, JobStatus::TimedOut);
        assert!(v.error.unwrap().contains("did not finish"));
    }

    #[tokio::test]
    async fn the_queue_limit_rejects_new_jobs_when_full() {
        let store = JobStore::new(&cfg(1, 2, 5_000, 60_000));
        let slow = FakeProber::slow(Duration::from_secs(30));
        store.submit(job("a.test"), slow.clone()).unwrap();
        store.submit(job("b.test"), slow.clone()).unwrap();
        assert!(matches!(
            store.submit(job("c.test"), slow),
            Err(SubmitError::Busy)
        ));
        assert_eq!(store.active(), 2);
    }

    #[tokio::test]
    async fn concurrency_is_capped() {
        let store = JobStore::new(&cfg(1, 5, 5_000, 60_000));
        let slow = FakeProber::slow(Duration::from_secs(30));
        let first = store.submit(job("a.test"), slow.clone()).unwrap();
        let second = store.submit(job("b.test"), slow).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(store.view(&first).unwrap().status, JobStatus::Running);
        assert_eq!(store.view(&second).unwrap().status, JobStatus::Queued);
    }

    #[tokio::test]
    async fn finished_jobs_expire_but_running_ones_do_not() {
        let store = JobStore::new(&cfg(2, 10, 5_000, 20));
        let done = store.submit(job("a.test"), FakeProber::ok()).unwrap();
        wait_finished(&store, &done).await;
        let running = store
            .submit(job("b.test"), FakeProber::slow(Duration::from_secs(30)))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(store.sweep(), 1);
        assert!(store.view(&done).is_none());
        assert!(store.view(&running).is_some());
        assert!(matches!(store.report(&done), ReportLookup::NotFound));
    }

    fn cooldown_cfg(cooldown_ms: u64) -> Config {
        Config {
            limits: crate::ratelimit::RateLimits {
                target_cooldown: Duration::from_millis(cooldown_ms),
                ..Default::default()
            },
            ..cfg(2, 10, 5000, 60_000)
        }
    }

    #[tokio::test]
    async fn a_repeat_within_the_cooldown_reuses_the_job() {
        let store = JobStore::new(&cooldown_cfg(60_000));
        let p = FakeProber::ok();
        let a = store
            .submit_keyed("k1".into(), job("a.test"), Arc::clone(&p), Box::new(()))
            .unwrap();
        let again = store
            .submit_keyed("k1".into(), job("a.test"), Arc::clone(&p), Box::new(()))
            .unwrap();
        let other = store
            .submit_keyed("k2".into(), job("a.test"), p, Box::new(()))
            .unwrap();
        let Submitted::New(id) = a else {
            panic!("first must be new")
        };
        assert_eq!(again, Submitted::Reused(id.clone()));
        assert!(matches!(other, Submitted::New(ref o) if *o != id));
        assert_eq!(store.recent("k1"), Some(id));
        assert_eq!(store.recent("nope"), None);
    }

    #[tokio::test]
    async fn cooldown_zero_never_reuses() {
        let store = JobStore::new(&cooldown_cfg(0));
        let p = FakeProber::ok();
        for _ in 0..2 {
            let r = store
                .submit_keyed("k".into(), job("a.test"), Arc::clone(&p), Box::new(()))
                .unwrap();
            assert!(matches!(r, Submitted::New(_)));
        }
    }

    #[tokio::test]
    async fn the_cooldown_ends_and_sweep_forgets_the_key() {
        let store = JobStore::new(&cooldown_cfg(30));
        let p = FakeProber::ok();
        let first = store
            .submit_keyed("k".into(), job("a.test"), Arc::clone(&p), Box::new(()))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(store.recent("k"), None);
        let second = store
            .submit_keyed("k".into(), job("a.test"), p, Box::new(()))
            .unwrap();
        assert_ne!(first, second);
        tokio::time::sleep(Duration::from_millis(80)).await;
        store.sweep();
        assert_eq!(store.recent("k"), None);
    }

    #[tokio::test]
    async fn the_hold_is_released_when_the_job_ends_or_is_reused() {
        let store = JobStore::new(&cooldown_cfg(60_000));
        let p = FakeProber::ok();
        let token = Arc::new(());
        store
            .submit_keyed(
                "k".into(),
                job("a.test"),
                Arc::clone(&p),
                Box::new(Arc::clone(&token)),
            )
            .unwrap();
        let reused = store
            .submit_keyed("k".into(), job("a.test"), p, Box::new(Arc::clone(&token)))
            .unwrap();
        assert!(matches!(reused, Submitted::Reused(_)));
        for _ in 0..300 {
            if Arc::strong_count(&token) == 1 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the hold was never released");
    }
}
