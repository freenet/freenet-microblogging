//! Small persistent network for live raven testing: 1 gateway + 2 peers.
//! Prints WS URLs in a grep-friendly format, then stays up until Ctrl+C.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let mut builder = freenet_test_network::TestNetwork::builder()
        .gateways(1)
        .peers(2)
        .preserve_temp_dirs_on_failure(true);
    // Point at a locally built freenet binary (e.g. a fix-branch build)
    // instead of the installed release from PATH.
    if let Some(bin) = std::env::var_os("FREENET_TEST_BINARY") {
        builder = builder.binary(freenet_test_network::FreenetBinary::Path(bin.into()));
    }
    let network = builder.build().await?;

    println!("RAVEN_NET_READY");
    println!("GATEWAY_WS={}", network.gateway(0).ws_url());
    for (i, url) in network.peer_ws_urls().iter().enumerate() {
        println!("PEER{}_WS={}", i, url);
    }

    tokio::signal::ctrl_c().await?;
    Ok(())
}
