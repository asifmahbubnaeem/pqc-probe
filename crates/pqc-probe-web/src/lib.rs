//! pqc-probe-web: the HTTP front end for pqc-probe.
//!
//! Flow: `POST /api/v1/probes` validates and resolves the target (the same policy as the CLI
//! uses for hosted mode: no private or internal addresses, a port allowlist), creates a job and
//! returns 202 with an id. A background task runs the probe under a global concurrency cap and a
//! deadline. `GET /api/v1/probes/{id}` reports status; `GET /api/v1/probes/{id}/report` returns
//! the same JSON document as `pqc-probe probe --output json` (schema in `schema/report-v1.json`).
//!
//! The probe itself and the DNS resolver are traits, so the whole service is testable without
//! a network.

pub mod api;
pub mod config;
pub mod error;
pub mod jobs;
pub mod model;
pub mod prober;
pub mod ratelimit;

#[cfg(test)]
mod testing;

pub use api::{router, AppState};
pub use config::Config;
pub use jobs::JobStore;
