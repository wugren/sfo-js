use std::path::Path;
use sfo_js::{JsEngine};

#[tokio::main]
async fn main() {
    let matches = clap::Command::new("js_run").arg(
        clap::Arg::new("file")
            .required(true)
            .help("The file to run")
            .index(1),
    ).get_matches();

    sfo_log::Logger::new("js_run")
        .set_log_to_file(false)
        .start().unwrap();

    let file = matches.get_one::<String>("file").unwrap();
    let provider_path = Path::new(file.as_str());
    let js_engine = JsEngine::builder().build_async().await.unwrap();
    if let Err(e) = js_engine.eval_file(provider_path).await {
        log::error!("Error: {}", e);
    }
}
