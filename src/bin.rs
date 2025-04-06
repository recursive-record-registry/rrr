use clap::Parser;
use color_eyre::eyre::Result;
use rrr::cmd::RrrArgs;
use tracing_error::ErrorLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

async fn setup_tracing() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(ErrorLayer::default())
        .with(EnvFilter::from_default_env())
        .try_init()?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_tracing().await?;
    RrrArgs::parse().process().await?;

    Ok(())
}
