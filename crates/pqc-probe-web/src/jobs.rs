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
        tokio::spawn(async move { store.run(task_id, job, prober).await });
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
}
