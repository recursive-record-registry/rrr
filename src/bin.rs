#![feature(async_closure)]

use clap::Parser;
use rrr::cmd::RrrArgs;

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    let args = RrrArgs::parse();

    args.process().await
}
