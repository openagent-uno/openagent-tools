#[cfg(target_os="macos")]
mod live_macos;
mod desktop;
mod live;
mod accessibility;
mod advanced;
mod capture;
mod input;
mod keys;
mod record;
mod scaling;
mod tool;

use anyhow::Result;
use rmcp::{ServiceExt, transport::stdio};
use tracing_subscriber::{EnvFilter, fmt};

fn main() -> anyhow::Result<()> {
    #[cfg(target_os="macos")]
    {
        // Cocoa owns the real main thread. Capture callbacks keep a live
        // application connection while protocol/encoder work runs off-thread.
        live_macos::application_initialize();
        let worker=std::thread::spawn(||tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(run()));
        while !worker.is_finished(){live_macos::application_pump();}
        worker.join().map_err(|_|anyhow::anyhow!("native host worker failed"))?
    }
    #[cfg(not(target_os="macos"))]
    tokio::runtime::Builder::new_multi_thread().enable_all().build()?.block_on(run())
}

async fn run() -> Result<()> {
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    if std::env::args().any(|arg| arg == "--desktop-stdio") { return desktop::serve(); }
    if std::env::args().any(|arg| arg == "--desktop-stream") { return live::serve(); }
    let server = tool::ComputerControlServer::new();
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
