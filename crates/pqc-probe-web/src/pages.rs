//! The browser-facing side: the form, the result page, the stylesheet and the security headers.
//! The form posts to the same submit path as the JSON API, so rate limits, policy and the
//! cooldown apply identically.

use crate::api::{submit, AppState, ClientIp};
use crate::html::{self, FormValues};
use crate::jobs::ReportLookup;
use crate::model::{is_valid_job_id, JobStatus, ProbeRequest};
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use pqc_probe_core::{ModeSelection, ProtocolSelection};
use serde::Deserialize;

/// No scripts, no inline styles, nothing loaded from elsewhere, no framing, forms only to us.
const CSP: &str = "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

/// Added to every response, JSON included.
pub async fn security_headers(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    resp
}

#[derive(Debug, Default, Deserialize)]
pub struct ProbeForm {
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub protocol: String,
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub tls_port: String,
    #[serde(default)]
    pub ssh_port: String,
}

impl ProbeForm {
    fn values(&self) -> FormValues {
        FormValues {
            target: self.target.clone(),
            protocol: self.protocol.clone(),
            mode: self.mode.clone(),
            tls_port: self.tls_port.clone(),
            ssh_port: self.ssh_port.clone(),
        }
    }
}

/// Turn what the form sent into the same request the JSON API takes. The message is shown to
/// the visitor.
pub fn form_to_request(f: &ProbeForm) -> Result<ProbeRequest, String> {
    let protocol = match f.protocol.as_str() {
        "" | "tls" => ProtocolSelection::Tls,
        "ssh" => ProtocolSelection::Ssh,
        "both" => ProtocolSelection::Both,
        _ => return Err("choose TLS, SSH or both".to_string()),
    };
    let mode = match f.mode.as_str() {
        "" => None,
        "vanilla" => Some(ModeSelection::Vanilla),
        "experimental" => Some(ModeSelection::Experimental),
        "both" => Some(ModeSelection::Both),
        _ => return Err("unknown mode".to_string()),
    };
    let port = |label: &str, v: &str| -> Result<Option<u16>, String> {
        let v = v.trim();
        if v.is_empty() {
            return Ok(None);
        }
        v.parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .map(Some)
            .ok_or_else(|| format!("{label} must be a number from 1 to 65535"))
    };
    Ok(ProbeRequest {
        target: f.target.clone(),
        protocol,
        mode,
        tls_port: port("The TLS port", &f.tls_port)?,
        ssh_port: port("The SSH port", &f.ssh_port)?,
    })
}

fn html_response(status: StatusCode, body: String) -> Response {
    (
        status,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        body,
    )
        .into_response()
}

fn offers(st: &AppState) -> String {
    let t = &st.config.tools;
    format!(
        "TLS modes: {}. SSH modes: {}.",
        t.available_modes(ProtocolSelection::Tls).join(", "),
        t.available_modes(ProtocolSelection::Ssh).join(", ")
    )
}

pub async fn index(State(st): State<AppState>) -> Response {
    html_response(
        StatusCode::OK,
        html::index_page(&FormValues::default(), None, &offers(&st)),
    )
}

pub async fn submit_form(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    form: Result<Form<ProbeForm>, FormRejection>,
) -> Response {
    let Form(f) = match form {
        Ok(f) => f,
        Err(rej) => {
            return html_response(
                rej.status(),
                html::index_page(
                    &FormValues::default(),
                    Some("the form could not be read"),
                    &offers(&st),
                ),
            )
        }
    };
    let values = f.values();
    let req = match form_to_request(&f) {
        Ok(r) => r,
        Err(message) => {
            return html_response(
                StatusCode::BAD_REQUEST,
                html::index_page(&values, Some(&message), &offers(&st)),
            )
        }
    };
    match submit(&st, ip, req).await {
        Ok((id, _reused)) => Redirect::to(&format!("/probes/{id}")).into_response(),
        Err(e) => {
            let mut resp = html_response(
                e.status,
                html::index_page(&values, Some(&e.message), &offers(&st)),
            );
            if let Some(secs) = e.retry_after {
                resp.headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from(secs));
            }
            resp
        }
    }
}

pub async fn job_page(State(st): State<AppState>, Path(id): Path<String>) -> Response {
    let not_found = || {
        html_response(
            StatusCode::NOT_FOUND,
            html::error_page(
                "No such probe",
                "Results are kept for a limited time after they finish.",
            ),
        )
    };
    if !is_valid_job_id(&id) {
        return not_found();
    }
    let Some(view) = st.store.view(&id) else {
        return not_found();
    };
    let report = match view.status {
        JobStatus::Succeeded => match st.store.report(&id) {
            ReportLookup::Ready(r) => Some(r),
            _ => None,
        },
        _ => None,
    };
    html_response(StatusCode::OK, html::job_page(&view, report.as_deref()))
}

pub async fn style() -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/css; charset=utf-8"),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=3600"),
            ),
        ],
        html::stylesheet(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::jobs::JobStore;
    use crate::ratelimit::{IpLimiter, RateLimits};
    use crate::testing::{FakeProber, FakeResolver};
    use crate::{router, AppState};
    use axum::body::Body;
    use axum::http::Request;
    use std::sync::Arc;
    use std::time::Duration;
    use tower::ServiceExt;

    fn app(prober: Arc<dyn crate::prober::Prober>) -> axum::Router {
        let config = Config {
            job_timeout: Duration::from_secs(5),
            limits: RateLimits {
                burst: 1000,
                per_minute: 6000,
                max_inflight: 1000,
                per_day: 100_000,
                target_cooldown: Duration::ZERO,
                trusted_proxies: vec![],
            },
            ..Config::default()
        };
        router(AppState {
            store: JobStore::new(&config),
            limiter: IpLimiter::new(config.limits.clone()),
            config: Arc::new(config),
            prober,
            resolver: Arc::new(FakeResolver),
        })
    }

    async fn call(
        app: &axum::Router,
        req: Request<Body>,
    ) -> (StatusCode, axum::http::HeaderMap, String) {
        let resp = app.clone().oneshot(req).await.unwrap();
        let (status, headers) = (resp.status(), resp.headers().clone());
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            headers,
            String::from_utf8_lossy(&bytes).into_owned(),
        )
    }

    fn get(uri: &str) -> Request<Body> {
        Request::builder().uri(uri).body(Body::empty()).unwrap()
    }

    fn form_post(body: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/probe")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[test]
    fn form_values_become_the_api_request() {
        let f = ProbeForm {
            target: "example.com".into(),
            protocol: "both".into(),
            mode: "vanilla".into(),
            tls_port: " 8443 ".into(),
            ssh_port: "".into(),
        };
        let r = form_to_request(&f).unwrap();
        assert_eq!(r.protocol, ProtocolSelection::Both);
        assert_eq!(r.mode, Some(ModeSelection::Vanilla));
        assert_eq!((r.tls_port, r.ssh_port), (Some(8443), None));
        let empty = form_to_request(&ProbeForm::default()).unwrap();
        assert_eq!((empty.protocol, empty.mode), (ProtocolSelection::Tls, None));
    }

    #[test]
    fn bad_form_values_are_explained() {
        let bad = |f: ProbeForm| form_to_request(&f).unwrap_err();
        let base = || ProbeForm {
            target: "a".into(),
            ..Default::default()
        };
        assert!(bad(ProbeForm {
            protocol: "ftp".into(),
            ..base()
        })
        .contains("choose"));
        assert!(bad(ProbeForm {
            mode: "fast".into(),
            ..base()
        })
        .contains("mode"));
        for p in ["0", "65536", "abc", "-1"] {
            assert!(
                bad(ProbeForm {
                    tls_port: p.into(),
                    ..base()
                })
                .contains("TLS port"),
                "{p}"
            );
        }
        assert!(bad(ProbeForm {
            ssh_port: "x".into(),
            ..base()
        })
        .contains("SSH port"));
    }

    #[tokio::test]
    async fn the_home_page_and_stylesheet_are_served_with_security_headers() {
        let app = app(FakeProber::ok());
        let (s, h, body) = call(&app, get("/")).await;
        assert_eq!(s, StatusCode::OK);
        assert!(h["content-type"].to_str().unwrap().starts_with("text/html"));
        assert!(body.contains("<form method=\"post\" action=\"/probe\">"));
        let csp = h["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("default-src 'none'") && csp.contains("frame-ancestors 'none'"));
        assert_eq!(h["x-content-type-options"], "nosniff");
        assert_eq!(h["referrer-policy"], "no-referrer");
        assert_eq!(h["x-frame-options"], "DENY");

        let (s, h, css) = call(&app, get("/static/style.css")).await;
        assert_eq!(s, StatusCode::OK);
        assert!(h["content-type"].to_str().unwrap().starts_with("text/css"));
        assert!(css.contains("--accent"));
    }

    #[tokio::test]
    async fn the_json_api_carries_the_security_headers_too() {
        let app = app(FakeProber::ok());
        let (_, h, _) = call(&app, get("/api/v1/meta")).await;
        assert_eq!(h["x-content-type-options"], "nosniff");
        assert!(h.contains_key("content-security-policy"));
    }

    #[tokio::test]
    async fn submitting_the_form_redirects_to_a_page_that_ends_with_the_report() {
        let app = app(FakeProber::ok());
        let (s, h, _) = call(&app, form_post("target=example.test&protocol=tls")).await;
        assert_eq!(s, StatusCode::SEE_OTHER);
        let loc = h["location"].to_str().unwrap().to_string();
        assert!(loc.starts_with("/probes/"), "{loc}");

        let mut body = String::new();
        for _ in 0..300 {
            let (s, _, b) = call(&app, get(&loc)).await;
            assert_eq!(s, StatusCode::OK);
            body = b;
            if !body.contains("http-equiv=\"refresh\"") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(body.contains("Report for example.test"), "{body}");
        assert!(body.contains("/api/v1/probes/"), "links to the JSON report");
    }

    #[tokio::test]
    async fn form_errors_come_back_as_the_form_with_the_message_and_an_escaped_echo() {
        let app = app(FakeProber::ok());
        // A hostile target is refused by the policy, and echoed back only escaped.
        let (s, _, body) = call(
            &app,
            form_post("target=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E&protocol=tls"),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert!(!body.contains("<script"), "{body}");
        assert!(body.contains("&lt;script&gt;"), "{body}");

        let (s, _, body) = call(&app, form_post("target=example.test&tls_port=abc")).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert!(body.contains("The TLS port must be a number"), "{body}");

        let (s, _, body) = call(&app, form_post("target=internal.test")).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert!(body.contains("not allowed"), "{body}");
    }

    #[tokio::test]
    async fn unknown_or_malformed_probe_pages_are_404() {
        let app = app(FakeProber::ok());
        for uri in [
            "/probes/nothing",
            "/probes/0123456789abcdef0123456789abcdef",
        ] {
            let (s, _, body) = call(&app, get(uri)).await;
            assert_eq!(s, StatusCode::NOT_FOUND, "{uri}");
            assert!(body.contains("No such probe"));
        }
    }

    #[tokio::test]
    async fn a_failed_probe_page_shows_the_reason() {
        let app = app(FakeProber::fails("the server hung up"));
        let (_, h, _) = call(&app, form_post("target=example.test")).await;
        let loc = h["location"].to_str().unwrap().to_string();
        let mut body = String::new();
        for _ in 0..300 {
            body = call(&app, get(&loc)).await.2;
            if !body.contains("http-equiv=\"refresh\"") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(body.contains("the server hung up"), "{body}");
        assert!(body.contains("failed"));
    }
}
