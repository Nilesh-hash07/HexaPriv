#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    privacy_relay::run_relay(8080).await
}
