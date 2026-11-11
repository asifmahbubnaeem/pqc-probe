//! pqc-probe-web entry point. Configuration comes from `PQC_WEB_*` environment variables
//! (see `docs/web.md`).

use anyhow::Result;
use pqc_probe_web::prober::{CliProber, SystemResolver};
use pqc_probe_web::ratelimit::IpLimiter;
use pqc_probe_web::{router, AppState, Config, JobStore};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = Config::from_env().map_err(|e| anyhow::anyhow!(e))?;
    let store = JobStore::new(&config);
    store.spawn_sweeper();
    let limiter = IpLimiter::new(config.limits.clone());
    limiter.spawn_pruner();

    let bind = config.bind;
    let prober = CliProber::new(config.tools.clone(), config.probe_timeout);
    let state = AppState {
        config: Arc::new(config),
        store,
        prober: Arc::new(prober),
        resolver: Arc::new(SystemResolver),
        limiter,
    };

    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, "pqc-probe-web listening");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("shutting down");
    })
    .await?;
    Ok(())
}
