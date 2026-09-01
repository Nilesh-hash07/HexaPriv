#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    privacy_client::run_client(None, None).await
}

