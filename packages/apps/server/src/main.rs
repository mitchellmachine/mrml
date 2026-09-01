use mrml_agent::{Config, MrmlAgent};
use mrml_server::ApiServer;

fn application_main() -> mrml_error::Result<()> {
    let config = Config::parse();
    let agent = MrmlAgent::new(config.clone());
    let certificate = mrml_runtime::environment_variable("MRML_TLS_CERT")
        .ok_or_else(|| mrml_error::message("MRML_TLS_CERT must name the HTTPS certificate PEM"))?;
    let private_key = mrml_runtime::environment_variable("MRML_TLS_KEY")
        .ok_or_else(|| mrml_error::message("MRML_TLS_KEY must name the HTTPS private-key PEM"))?;
    if mrml_runtime::environment_variable("MRML_TLS_DEVELOPMENT_RAW_PEM").as_deref() != Some("1") {
        return Err(mrml_error::message(
            "raw TLS private-key files are development-only; use the certificate identity service",
        ));
    }
    let api_token = mrml_runtime::environment_variable("MRML_API_TOKEN").ok_or_else(|| {
        mrml_error::message("MRML_API_TOKEN must contain a high-entropy bearer token")
    })?;
    let certificate = mrml_runtime::read_file_bounded(&certificate, 1024 * 1024)?;
    let private_key = mrml_runtime::read_file_bounded(&private_key, 64 * 1024)?;
    ApiServer::new(agent.get_client_arc(), config.port)
        .with_bearer_token(api_token)?
        .with_development_tls_pem(&certificate, &private_key)?
        .run()
}

fn main() {
    if let Err(error) = application_main() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
