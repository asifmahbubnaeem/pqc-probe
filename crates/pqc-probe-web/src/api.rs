//! HTTP routes. Everything under `/api/v1` is JSON; errors use the shape in [`crate::error`].

use crate::config::Config;
use crate::error::ApiError;
use crate::jobs::{JobStore, ReportLookup, SubmitError, Submitted};
use crate::model::{is_valid_job_id, Created, JobStatus, ProbeRequest};
use crate::pages;
use crate::prober::{ProbeJob, Prober, Resolver};
use crate::ratelimit::{client_ip, IpLimiter};
use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use pqc_probe_core::policy::Policy;
use pqc_probe_core::{ModeSelection, ProtocolSelection, SCHEMA_VERSION};
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

/// Request bodies are tiny; anything bigger is refused before it is parsed.
const MAX_BODY_BYTES: usize = 8 * 1024;
/// Hint for clients when the queue is full.
const BUSY_RETRY_SECS: u64 = 5;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub store: Arc<JobStore>,
    pub prober: Arc<dyn Prober>,
    pub resolver: Arc<dyn Resolver>,
    pub limiter: Arc<IpLimiter>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(pages::index))
        .route("/probe", post(pages::submit_form))
        .route("/probes/{id}", get(pages::job_page))
        .route("/static/style.css", get(pages::style))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/api/v1/meta", get(meta))
        .route("/api/v1/probes", post(create_probe))
        .route("/api/v1/probes/{id}", get(get_probe))
        .route("/api/v1/probes/{id}/report", get(get_report))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(axum::middleware::map_response(pages::security_headers))
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz(State(st): State<AppState>) -> Response {
    if st.store.active() < st.store.queue_limit() {
        (StatusCode::OK, "ready").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "busy").into_response()
    }
}

async fn meta(State(st): State<AppState>) -> Json<serde_json::Value> {
    let c = &st.config;
    Json(json!({
        "tool": { "name": "pqc-probe", "version": env!("CARGO_PKG_VERSION") },
        "schema_version": SCHEMA_VERSION,
        "allowed_ports": c.allowed_ports,
        "modes": {
            "tls": c.tools.available_modes(ProtocolSelection::Tls),
            "ssh": c.tools.available_modes(ProtocolSelection::Ssh),
        },
        "rate_limits": {
            "burst": c.limits.burst,
            "per_minute": c.limits.per_minute,
            "max_in_flight": c.limits.max_inflight,
            "per_day": c.limits.per_day,
            "target_cooldown_seconds": c.limits.target_cooldown.as_secs(),
        },
        "limits": {
            "max_concurrent": c.max_concurrent,
            "queue_limit": c.queue_limit,
            "job_timeout_seconds": c.job_timeout.as_secs(),
            "result_ttl_seconds": c.result_ttl.as_secs(),
        },
    }))
}

/// The address a request came from, after applying the trusted-proxy rules.
pub struct ClientIp(pub IpAddr);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip())
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let values: Vec<&str> = parts
            .headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        let forwarded = (!values.is_empty()).then(|| values.join(","));
        Ok(ClientIp(client_ip(
            peer,
            forwarded.as_deref(),
            &state.limiter.limits().trusted_proxies,
        )))
    }
}

/// What makes two requests "the same target" for the cooldown. Names are compared as written
/// (lower-cased); two spellings of one host get separate entries and are still caught by the
/// per-client limits.
fn dedupe_key(
    host: &str,
    protocol: ProtocolSelection,
    mode: ModeSelection,
    tls_port: Option<u16>,
    ssh_port: Option<u16>,
) -> String {
    format!(
        "{}|{protocol:?}|{mode:?}|{tls_port:?}|{ssh_port:?}",
        host.to_ascii_lowercase()
    )
}

fn created_response(st: &AppState, id: String, reused: bool) -> Response {
    let status = if reused {
        st.store
            .view(&id)
            .map(|v| v.status)
            .unwrap_or(JobStatus::Queued)
    } else {
        JobStatus::Queued
    };
    let status_url = format!("/api/v1/probes/{id}");
    let created = Created {
        id,
        status,
        report_url: format!("{status_url}/report"),
        status_url: status_url.clone(),
        reused,
    };
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&status_url) {
        headers.insert(header::LOCATION, v);
    }
    (StatusCode::ACCEPTED, headers, Json(created)).into_response()
}

/// Split `host` or `host:port`. Host syntax is checked later by the policy; this only separates
/// the port and refuses anything that is clearly not a target.
fn split_target(input: &str) -> Result<(String, Option<u16>), ApiError> {
    let input = input.trim();
    if input.is_empty() || input.len() > 300 {
        return Err(ApiError::invalid_request("target must be 1-300 characters"));
    }
    match input.rsplit_once(':') {
        None => Ok((input.to_string(), None)),
        Some((host, port)) => {
            let port: u16 = port.parse().map_err(|_| {
                ApiError::invalid_request("the port in target must be a number from 1 to 65535")
            })?;
            Ok((host.to_string(), Some(port)))
        }
    }
}

fn json_rejection(rej: JsonRejection) -> ApiError {
    let status = rej.status();
    let (code, message) = match status {
        StatusCode::PAYLOAD_TOO_LARGE => (
            "payload_too_large",
            format!("request body is larger than {MAX_BODY_BYTES} bytes"),
        ),
        StatusCode::UNSUPPORTED_MEDIA_TYPE => (
            "unsupported_media_type",
            "send the request with Content-Type: application/json".to_string(),
        ),
        _ => ("invalid_request", rej.body_text()),
    };
    let mut e = ApiError::new(status, code, message);
    if code == "invalid_request" {
        e = ApiError::invalid_request(e.message);
    }
    e
}

async fn create_probe(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    payload: Result<Json<ProbeRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let Json(req) = payload.map_err(json_rejection)?;
    let (id, reused) = submit(&st, ip, req).await?;
    Ok(created_response(&st, id, reused))
}

/// Validate a request, apply the limits and start (or reuse) a job. Shared by the JSON API and
/// the HTML form. Returns the job id and whether an earlier job was reused.
pub(crate) async fn submit(
    st: &AppState,
    ip: IpAddr,
    req: ProbeRequest,
) -> Result<(String, bool), ApiError> {
    let (host, port_in_target) = split_target(&req.target)?;

    let want_tls = matches!(
        req.protocol,
        ProtocolSelection::Tls | ProtocolSelection::Both
    );
    let want_ssh = matches!(
        req.protocol,
        ProtocolSelection::Ssh | ProtocolSelection::Both
    );
    // Refuse a mode this server cannot run before spending any DNS or queue slot on it.
    let mode = st
        .config
        .tools
        .resolve_mode(req.protocol, req.mode)
        .map_err(|m| {
            ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "mode_unavailable", m)
                .with_hint("See GET /api/v1/meta for the modes this server offers.")
        })?;
    // The port written in `target` belongs to TLS, unless only SSH was asked for.
    let tls_port = want_tls.then(|| req.tls_port.or(port_in_target).unwrap_or(443));
    let ssh_port = want_ssh.then(|| {
        let from_target = if want_tls { None } else { port_in_target };
        req.ssh_port.or(from_target).unwrap_or(22)
    });

    // A repeat of a recent request gets the earlier job back: no new probe, no DNS lookup, and
    // nothing counted against the client.
    let key = dedupe_key(&host, req.protocol, mode, tls_port, ssh_port);
    if let Some(id) = st.store.recent(&key) {
        return Ok((id, true));
    }
    // From here on the request costs work (DNS at least), so it counts. The guard holds the
    // client's in-flight slot; it is released on any early return and when the job ends.
    let guard = st
        .limiter
        .try_start(ip, Instant::now())
        .map_err(|d| ApiError::rate_limited(&d))?;

    let policy = Policy {
        allowed_ports: st.config.allowed_ports.clone(),
    };
    let tls = match tls_port {
        Some(p) => Some(st.resolver.prepare(&host, p, &policy).await?),
        None => None,
    };
    let ssh = match ssh_port {
        Some(p) => Some(st.resolver.prepare(&host, p, &policy).await?),
        None => None,
    };

    let job = ProbeJob {
        request: req,
        mode,
        tls,
        ssh,
    };
    let submitted = st
        .store
        .submit_keyed(key, job, Arc::clone(&st.prober), Box::new(guard))
        .map_err(|SubmitError::Busy| ApiError::busy(BUSY_RETRY_SECS))?;
    Ok(match submitted {
        Submitted::New(id) => (id, false),
        Submitted::Reused(id) => (id, true),
    })
}

async fn get_probe(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    if !is_valid_job_id(&id) {
        return Err(ApiError::not_found());
    }
    match st.store.view(&id) {
        Some(view) => Ok(Json(view).into_response()),
        None => Err(ApiError::not_found()),
    }
}

async fn get_report(
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    if !is_valid_job_id(&id) {
        return Err(ApiError::not_found());
    }
    match st.store.report(&id) {
        ReportLookup::NotFound => Err(ApiError::not_found()),
        ReportLookup::NotReady(status) => {
            let mut e = ApiError::new(
                StatusCode::CONFLICT,
                "not_ready",
                format!("the probe is still {}", status_word(status)),
            )
            .with_hint("Poll the status URL until the status is succeeded, failed or timed_out.");
            e.retry_after = Some(1);
            Err(e)
        }
        ReportLookup::Unavailable { status, error } => {
            let code = if status == JobStatus::TimedOut {
                "job_timed_out"
            } else {
                "job_failed"
            };
            Err(ApiError::new(
                StatusCode::CONFLICT,
                code,
                error.unwrap_or_else(|| "the probe produced no report".to_string()),
            ))
        }
        ReportLookup::Ready(report) => Ok(Json(&*report).into_response()),
    }
}

fn status_word(s: JobStatus) -> &'static str {
    match s {
        JobStatus::Queued => "queued",
        JobStatus::Running => "running",
        JobStatus::Succeeded => "succeeded",
        JobStatus::Failed => "failed",
        JobStatus::TimedOut => "timed out",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{FakeProber, FakeResolver};
    use axum::body::Body;
    use axum::http::Request;
    use std::time::Duration;
    use tower::ServiceExt;

    fn state(config: Config, prober: Arc<dyn Prober>) -> AppState {
        AppState {
            store: JobStore::new(&config),
            limiter: IpLimiter::new(config.limits.clone()),
            config: Arc::new(config),
            prober,
            resolver: Arc::new(FakeResolver),
        }
    }

    fn small_config() -> Config {
        Config {
            max_concurrent: 2,
            queue_limit: 10,
            job_timeout: Duration::from_secs(5),
            result_ttl: Duration::from_secs(60),
            limits: crate::ratelimit::RateLimits {
                burst: 1000,
                per_minute: 6000,
                max_inflight: 1000,
                per_day: 100_000,
                target_cooldown: Duration::ZERO,
                trusted_proxies: vec![],
            },
            tools: crate::config::ToolPaths {
                openssl_oqs: Some("openssl-oqs".into()),
                ssh_oqs: Some("ssh-oqs".into()),
                ..Default::default()
            },
            ..Config::default()
        }
    }

    async fn send(app: &Router, req: Request<Body>) -> (StatusCode, HeaderMap, serde_json::Value) {
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, headers, value)
    }

    fn post_json(body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/api/v1/probes")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn get_req(uri: &str) -> Request<Body> {
        Request::builder().uri(uri).body(Body::empty()).unwrap()
    }

    async fn wait_done(app: &Router, id: &str) -> serde_json::Value {
        for _ in 0..300 {
            let (_, _, v) = send(app, get_req(&format!("/api/v1/probes/{id}"))).await;
            let status = v["status"].as_str().unwrap_or("").to_string();
            if matches!(status.as_str(), "succeeded" | "failed" | "timed_out") {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("probe {id} did not finish");
    }

    #[test]
    fn target_splitting() {
        assert_eq!(
            split_target("example.com").unwrap(),
            ("example.com".to_string(), None)
        );
        assert_eq!(
            split_target(" example.com:8443 ").unwrap(),
            ("example.com".to_string(), Some(8443))
        );
        assert!(split_target("").is_err());
        assert!(split_target("example.com:abc").is_err());
        assert!(split_target("example.com:99999").is_err());
        assert!(split_target(&"a".repeat(301)).is_err());
    }

    #[tokio::test]
    async fn health_and_meta() {
        let app = router(state(small_config(), FakeProber::ok()));
        let (s, _, _) = send(&app, get_req("/healthz")).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _, _) = send(&app, get_req("/readyz")).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _, v) = send(&app, get_req("/api/v1/meta")).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["limits"]["max_concurrent"], 2);
        assert!(v["allowed_ports"].as_array().unwrap().contains(&json!(443)));
    }

    #[tokio::test]
    async fn an_unavailable_mode_is_refused_with_422_and_the_default_degrades() {
        // No experimental tools configured.
        let cfg = Config {
            tools: Default::default(),
            ..small_config()
        };
        let app = router(state(cfg, FakeProber::ok()));
        let (s, _, v) = send(
            &app,
            post_json(r#"{"target":"example.test","mode":"both"}"#),
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(v["error"]["code"], "mode_unavailable");

        let (s, _, v) = send(&app, post_json(r#"{"target":"example.test"}"#)).await;
        assert_eq!(s, StatusCode::ACCEPTED);
        let id = v["id"].as_str().unwrap().to_string();
        wait_done(&app, &id).await;
        let (_, _, report) = send(&app, get_req(&format!("/api/v1/probes/{id}/report"))).await;
        assert_eq!(report["request"]["mode"], "vanilla");

        let (_, _, meta) = send(&app, get_req("/api/v1/meta")).await;
        assert_eq!(meta["modes"]["tls"], json!(["vanilla"]));
    }

    #[tokio::test]
    async fn submit_poll_and_fetch_the_report() {
        let app = router(state(small_config(), FakeProber::ok()));
        let (s, h, v) = send(
            &app,
            post_json(r#"{"target":"example.test","protocol":"both","mode":"both"}"#),
        )
        .await;
        assert_eq!(s, StatusCode::ACCEPTED);
        let id = v["id"].as_str().unwrap().to_string();
        assert!(is_valid_job_id(&id));
        assert_eq!(v["status"], "queued");
        assert_eq!(
            h.get("location").unwrap().to_str().unwrap(),
            format!("/api/v1/probes/{id}")
        );

        let done = wait_done(&app, &id).await;
        assert_eq!(done["status"], "succeeded");
        assert_eq!(done["target"], "example.test");

        let (s, _, report) = send(&app, get_req(&format!("/api/v1/probes/{id}/report"))).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(report["schema_version"], 1);
        assert_eq!(report["target"]["host"], "example.test");
        assert_eq!(report["target"]["tls_port"], 443);
        assert_eq!(report["target"]["ssh_port"], 22);
    }

    #[tokio::test]
    async fn ports_follow_the_protocol_rules() {
        let app = router(state(small_config(), FakeProber::ok()));
        // port in target -> TLS; SSH keeps its default
        let (_, _, v) = send(
            &app,
            post_json(r#"{"target":"example.test:8443","protocol":"both"}"#),
        )
        .await;
        let id = v["id"].as_str().unwrap().to_string();
        wait_done(&app, &id).await;
        let (_, _, r) = send(&app, get_req(&format!("/api/v1/probes/{id}/report"))).await;
        assert_eq!(r["target"]["tls_port"], 8443);
        assert_eq!(r["target"]["ssh_port"], 22);
        // ssh only -> port in target is the SSH port
        let (_, _, v) = send(
            &app,
            post_json(r#"{"target":"example.test:2222","protocol":"ssh"}"#),
        )
        .await;
        let id = v["id"].as_str().unwrap().to_string();
        wait_done(&app, &id).await;
        let (_, _, r) = send(&app, get_req(&format!("/api/v1/probes/{id}/report"))).await;
        assert!(r["target"]["tls_port"].is_null());
        assert_eq!(r["target"]["ssh_port"], 2222);
        // explicit override wins
        let (_, _, v) = send(
            &app,
            post_json(r#"{"target":"example.test","tls_port":8443}"#),
        )
        .await;
        let id = v["id"].as_str().unwrap().to_string();
        wait_done(&app, &id).await;
        let (_, _, r) = send(&app, get_req(&format!("/api/v1/probes/{id}/report"))).await;
        assert_eq!(r["target"]["tls_port"], 8443);
    }

    #[tokio::test]
    async fn private_and_unresolvable_targets_are_refused_and_create_no_job() {
        let st = state(small_config(), FakeProber::ok());
        let store = Arc::clone(&st.store);
        let app = router(st);
        let (s, _, v) = send(&app, post_json(r#"{"target":"internal.test"}"#)).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(v["error"]["code"], "target_not_allowed");
        assert!(!v["error"]["message"].as_str().unwrap().contains("10.0.0.5"));
        assert!(v["error"].get("hint").is_some());
        let (s, _, v) = send(&app, post_json(r#"{"target":"nxdomain.test"}"#)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(v["error"]["code"], "unresolvable_target");
        let (s, _, v) = send(&app, post_json(r#"{"target":"example.test:25"}"#)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(v["error"]["code"], "port_not_allowed");
        let (s, _, v) = send(&app, post_json(r#"{"target":"http://example.test/"}"#)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert!(
            ["invalid_target", "invalid_request"].contains(&v["error"]["code"].as_str().unwrap())
        );
        assert_eq!(store.active(), 0);
    }

    #[tokio::test]
    async fn malformed_requests_get_stable_error_codes() {
        let app = router(state(small_config(), FakeProber::ok()));
        for body in [
            "not json",
            r#"{"protocol":"tls"}"#,
            r#"{"target":"example.test","protocol":"ftp"}"#,
            r#"{"target":"example.test","surprise":1}"#,
        ] {
            let (s, _, v) = send(&app, post_json(body)).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(v["error"]["code"], "invalid_request", "{body}");
            assert!(v["error"]["hint"].is_string());
        }
        let no_ct = Request::builder()
            .method("POST")
            .uri("/api/v1/probes")
            .body(Body::from(r#"{"target":"example.test"}"#))
            .unwrap();
        let (s, _, v) = send(&app, no_ct).await;
        assert_eq!(s, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(v["error"]["code"], "unsupported_media_type");
        let big = format!(r#"{{"target":"{}"}}"#, "a".repeat(9 * 1024));
        let (s, _, v) = send(&app, post_json(&big)).await;
        assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(v["error"]["code"], "payload_too_large");
    }

    #[tokio::test]
    async fn unknown_or_malformed_ids_are_404_and_never_echoed() {
        let app = router(state(small_config(), FakeProber::ok()));
        for uri in [
            "/api/v1/probes/0123456789abcdef0123456789abcdef",
            "/api/v1/probes/0123456789abcdef0123456789abcdef/report",
            "/api/v1/probes/not-an-id",
            "/api/v1/probes/..%2f..%2fetc%2fpasswd",
        ] {
            let (s, _, v) = send(&app, get_req(uri)).await;
            assert_eq!(s, StatusCode::NOT_FOUND, "{uri}");
            assert_eq!(v["error"]["code"], "not_found");
            assert!(!v.to_string().contains("passwd"));
        }
    }

    #[tokio::test]
    async fn report_before_completion_is_409_not_ready() {
        let app = router(state(
            small_config(),
            FakeProber::slow(Duration::from_secs(30)),
        ));
        let (_, _, v) = send(&app, post_json(r#"{"target":"example.test"}"#)).await;
        let id = v["id"].as_str().unwrap().to_string();
        let (s, h, v) = send(&app, get_req(&format!("/api/v1/probes/{id}/report"))).await;
        assert_eq!(s, StatusCode::CONFLICT);
        assert_eq!(v["error"]["code"], "not_ready");
        assert!(h.get("retry-after").is_some());
    }

    #[tokio::test]
    async fn failed_and_timed_out_jobs_say_why() {
        let app = router(state(
            small_config(),
            FakeProber::fails("the server hung up"),
        ));
        let (_, _, v) = send(&app, post_json(r#"{"target":"example.test"}"#)).await;
        let id = v["id"].as_str().unwrap().to_string();
        let done = wait_done(&app, &id).await;
        assert_eq!(done["status"], "failed");
        assert_eq!(done["error"], "the server hung up");
        let (s, _, v) = send(&app, get_req(&format!("/api/v1/probes/{id}/report"))).await;
        assert_eq!(s, StatusCode::CONFLICT);
        assert_eq!(v["error"]["code"], "job_failed");

        let mut cfg = small_config();
        cfg.job_timeout = Duration::from_millis(50);
        let app = router(state(cfg, FakeProber::slow(Duration::from_secs(30))));
        let (_, _, v) = send(&app, post_json(r#"{"target":"example.test"}"#)).await;
        let id = v["id"].as_str().unwrap().to_string();
        let done = wait_done(&app, &id).await;
        assert_eq!(done["status"], "timed_out");
        let (s, _, v) = send(&app, get_req(&format!("/api/v1/probes/{id}/report"))).await;
        assert_eq!(s, StatusCode::CONFLICT);
        assert_eq!(v["error"]["code"], "job_timed_out");
    }

    #[tokio::test]
    async fn a_full_queue_answers_503_with_retry_after_and_readyz_flips() {
        let mut cfg = small_config();
        cfg.max_concurrent = 1;
        cfg.queue_limit = 1;
        let app = router(state(cfg, FakeProber::slow(Duration::from_secs(30))));
        let (s, _, _) = send(&app, post_json(r#"{"target":"example.test"}"#)).await;
        assert_eq!(s, StatusCode::ACCEPTED);
        let (s, h, v) = send(&app, post_json(r#"{"target":"example.test"}"#)).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(v["error"]["code"], "busy");
        assert!(h.get("retry-after").is_some());
        let (s, _, _) = send(&app, get_req("/readyz")).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
        let (s, _, _) = send(&app, get_req("/healthz")).await;
        assert_eq!(s, StatusCode::OK);
    }

    fn post_from(body: &str, peer: &str, xff: Option<&str>) -> Request<Body> {
        let mut b = Request::builder()
            .method("POST")
            .uri("/api/v1/probes")
            .header("content-type", "application/json")
            .extension(ConnectInfo(SocketAddr::new(peer.parse().unwrap(), 40000)));
        if let Some(x) = xff {
            b = b.header("x-forwarded-for", x);
        }
        b.body(Body::from(body.to_string())).unwrap()
    }

    fn limited(burst: u32, max_inflight: u32, cooldown: u64, proxies: &[&str]) -> Config {
        Config {
            limits: crate::ratelimit::RateLimits {
                burst,
                per_minute: 6,
                max_inflight,
                per_day: 1000,
                target_cooldown: Duration::from_secs(cooldown),
                trusted_proxies: proxies.iter().map(|p| p.parse().unwrap()).collect(),
            },
            ..small_config()
        }
    }

    const BODY: &str = r#"{"target":"example.test"}"#;

    #[tokio::test]
    async fn the_third_request_in_a_burst_of_two_gets_429_with_retry_after() {
        let app = router(state(limited(2, 100, 0, &[]), FakeProber::ok()));
        for _ in 0..2 {
            let (s, _, _) = send(&app, post_from(BODY, "198.51.100.1", None)).await;
            assert_eq!(s, StatusCode::ACCEPTED);
        }
        let (s, h, v) = send(&app, post_from(BODY, "198.51.100.1", None)).await;
        assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(v["error"]["code"], "rate_limited");
        let retry: u64 = h
            .get("retry-after")
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!((1..=60).contains(&retry));
        let (s, _, _) = send(&app, post_from(BODY, "198.51.100.2", None)).await;
        assert_eq!(s, StatusCode::ACCEPTED, "another client is unaffected");
    }

    #[tokio::test]
    async fn x_forwarded_for_counts_only_from_a_trusted_proxy() {
        let app = router(state(limited(1, 100, 0, &["10.0.0.1"]), FakeProber::ok()));
        // Behind the trusted proxy, different forwarded clients have their own budgets.
        let (s, _, _) = send(&app, post_from(BODY, "10.0.0.1", Some("203.0.113.1"))).await;
        assert_eq!(s, StatusCode::ACCEPTED);
        let (s, _, _) = send(&app, post_from(BODY, "10.0.0.1", Some("203.0.113.2"))).await;
        assert_eq!(s, StatusCode::ACCEPTED);
        let (s, _, _) = send(&app, post_from(BODY, "10.0.0.1", Some("203.0.113.1"))).await;
        assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
        // A direct client cannot get a fresh budget by lying in the header.
        let (s, _, _) = send(&app, post_from(BODY, "198.51.100.9", Some("203.0.113.50"))).await;
        assert_eq!(s, StatusCode::ACCEPTED);
        let (s, _, _) = send(&app, post_from(BODY, "198.51.100.9", Some("203.0.113.51"))).await;
        assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn too_many_probes_in_flight_gets_429() {
        let app = router(state(
            limited(100, 1, 0, &[]),
            FakeProber::slow(Duration::from_secs(30)),
        ));
        let (s, _, _) = send(&app, post_from(BODY, "198.51.100.1", None)).await;
        assert_eq!(s, StatusCode::ACCEPTED);
        let (s, _, v) = send(&app, post_from(BODY, "198.51.100.1", None)).await;
        assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(v["error"]["code"], "rate_limited");
    }

    #[tokio::test]
    async fn a_repeat_request_returns_the_earlier_job_and_costs_nothing() {
        // Burst of one: the repeat must not need a token.
        let app = router(state(limited(1, 100, 60, &[]), FakeProber::ok()));
        let (s, _, first) = send(&app, post_from(BODY, "198.51.100.1", None)).await;
        assert_eq!(s, StatusCode::ACCEPTED);
        assert_eq!(first["reused"], false);
        let (s, h, again) = send(&app, post_from(BODY, "198.51.100.1", None)).await;
        assert_eq!(s, StatusCode::ACCEPTED);
        assert_eq!(again["reused"], true);
        assert_eq!(again["id"], first["id"]);
        let id = first["id"].as_str().unwrap();
        assert_eq!(
            h.get("location").unwrap().to_str().unwrap(),
            format!("/api/v1/probes/{id}")
        );
        // A different target is new work, and the token is gone.
        let (s, _, _) = send(
            &app,
            post_from(r#"{"target":"example.test:8443"}"#, "198.51.100.1", None),
        )
        .await;
        assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    }
}
