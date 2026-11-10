//! The API error shape: `{"error":{"code":"...","message":"...","hint":null}}`.
//! `code` values are stable and part of the API contract; `message` is for humans.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use pqc_probe_core::policy::PolicyError;
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub hint: Option<String>,
    pub retry_after: Option<u64>,
}

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorInner,
}

#[derive(Serialize)]
struct ErrorInner {
    code: &'static str,
    message: String,
    hint: Option<String>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            hint: None,
            retry_after: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", message).with_hint(
            "POST JSON like {\"target\":\"example.com\",\"protocol\":\"tls\",\"mode\":\"both\"}",
        )
    }

    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "no such probe")
            .with_hint("Results are kept for a limited time after they finish.")
    }

    pub fn busy(retry_after: u64) -> Self {
        let mut e = Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "busy",
            "too many probes are queued or running",
        )
        .with_hint("Retry after the number of seconds in the Retry-After header.");
        e.retry_after = Some(retry_after);
        e
    }
}

impl From<PolicyError> for ApiError {
    fn from(e: PolicyError) -> Self {
        match e {
            PolicyError::InvalidHost(_, why) => Self::new(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                format!("the target host is not valid: {why}"),
            )
            .with_hint("Use a DNS name or an IPv4 address, without scheme, path or credentials."),
            PolicyError::PortNotAllowed(port, allowed) => Self::new(
                StatusCode::BAD_REQUEST,
                "port_not_allowed",
                format!("port {port} is not allowed on this service"),
            )
            .with_hint(format!("Allowed ports: {allowed}")),
            PolicyError::NoAddress(_) => Self::new(
                StatusCode::BAD_REQUEST,
                "unresolvable_target",
                "the target host name has no IPv4 address",
            )
            .with_hint("Only IPv4 targets are supported."),
            // The detail (resolver errors can name internal DNS servers) goes to the log only.
            PolicyError::ResolveFailed(host, why) => {
                tracing::warn!(%host, %why, "DNS lookup failed");
                Self::new(
                    StatusCode::BAD_REQUEST,
                    "unresolvable_target",
                    "the DNS lookup for the target failed or timed out",
                )
                .with_hint("Check the spelling, or try again in a moment.")
            }
            // Deliberately does not echo the resolved address: for split-horizon DNS that would
            // tell the caller about internal addressing.
            PolicyError::BlockedAddress { reason, .. } => Self::new(
                StatusCode::FORBIDDEN,
                "target_not_allowed",
                format!("the target resolves to an address that is not allowed ({reason})"),
            )
            .with_hint("This service only probes publicly routable hosts."),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ErrorBody {
            error: ErrorInner {
                code: self.code,
                message: self.message,
                hint: self.hint,
            },
        });
        let mut resp = (self.status, body).into_response();
        if let Some(secs) = self.retry_after {
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(secs));
        }
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_failure_and_missing_ipv4_are_told_apart() {
        let none: ApiError = PolicyError::NoAddress("a.test".into()).into();
        let failed: ApiError =
            PolicyError::ResolveFailed("a.test".into(), "internal-dns.corp refused".into()).into();
        assert_eq!(none.code, "unresolvable_target");
        assert_eq!(failed.code, "unresolvable_target");
        assert!(none.message.contains("no IPv4"));
        assert!(failed.message.contains("failed or timed out"));
        assert!(
            !failed.message.contains("internal-dns"),
            "resolver detail must not leak"
        );
    }
}
