use std::borrow::Borrow;
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use axum::{AddExtensionLayer, Json, Router};
use axum::body::Body;
use axum::extract::Extension;
use axum::handler::{get, post};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use clap::{App, Arg, SubCommand};
use hmac::Hmac;
use hyper::{Request, Response, Uri};
use hyper::header::HeaderValue;
use hyperlocal::{UnixClientExt, UnixServerExt};
use serde::{de, Deserialize, ser, Serialize};
use sha2::Sha256;
use thiserror::Error;
use tokio::io;
use tower::ServiceBuilder;
use tower_http::auth::RequireAuthorizationLayer;
use tower_http::trace::TraceLayer;

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug)]
struct Config {
    key: String,
    users: HashMap<String, Vec<String>>,
    #[serde(default)]
    allow_update: bool,
    #[serde(default)]
    pgp_public_key: String,
}

pub type HmacSha256 = Hmac<Sha256>;

async fn fetch_keys(Json(payload): Json<String>, cfg: axum::extract::Extension<Arc<Config>>) -> Result<Json<Vec<String>>, KeylometerError> {
    let k = do_keys(payload, cfg).await?;
    Ok(Json::from(k))
}

async fn do_keys(username: String, cfg: Extension<Arc<Config>>) -> Result<Vec<String>, KeylometerError> {
    let https = hyper_tls::HttpsConnector::new();
    let client = hyper::Client::builder().build::<_, hyper::Body>(https);

    fn url(username: String) -> Uri {
        let u = urlencoding::encode(username.as_str());
        let s = &format!("https://github.com/{}.keys", u);
        Uri::try_from(s).unwrap()
    }

    let v = vec![];
    let usernames = cfg.users.get(&username).unwrap_or(&v);


    let responses = usernames.iter().map(|n| client.get(url(n.clone()))).map(tokio::spawn).collect::<Vec<_>>();
    let reses = futures::future::join_all(responses).await;
    let mut strings = Vec::new();
    for rese in reses {
        let r = rese.map_err(|_| KeylometerError::Meme("Foo".to_string()))?;
        let r: Response<hyper::Body> = r?;
        let b = hyper::body::to_bytes(r).await?;
        let s = String::from_utf8(b.to_vec())?;
        let b = s.lines();
        for stronk in b {
            strings.push(String::from(stronk));
        }
    }
    Ok(strings)
}

async fn run_socket(socket_path: &str, r: Config) -> Result<(), KeylometerError> {
    let path = Path::new(socket_path);
    if tokio::fs::remove_file(path).await.is_ok() { tracing::info!("Removed old socket") }

    let middlewares = ServiceBuilder::new()
        .layer(RequireAuthorizationLayer::bearer(r.key.as_str()));

    let config = Arc::new(r);

    let app = Router::new().route("/", get(|| async { "Hello, World!" })).route("/keys", post(fetch_keys))
        .layer(TraceLayer::new_for_http())
        .layer(AddExtensionLayer::new(config.clone()));
    let app_http = Router::new().layer(middlewares).route("/", get(|| async { "Hello, World!" })).route("/keys", post(fetch_keys))
        .layer(TraceLayer::new_for_http())
        .layer(AddExtensionLayer::new(config));


    let (a, b) = tokio::join!(axum::Server::bind_unix(path)?
        .serve(app.into_make_service()), axum::Server::bind(&"0.0.0.0:3000".parse()?).serve(app_http.into_make_service()));
    a?;
    b?;

    Ok(())
}

#[derive(Error, Debug)]
pub enum KeylometerError {
    #[error("Hyper error: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("IO error: {0}")]
    IO(#[from] io::Error),
    #[error("AddrParseError: {0}")]
    AddrParse(#[from] std::net::AddrParseError),
    #[error("JoinError: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("Utf8Error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("MemeError: {0}")]
    Meme(String),
    #[error("SerdeJsonError: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("SerdeYamlError: {0}")]
    SerdeYaml(#[from] serde_yaml::Error),
    #[error("InvalidHeaderValue: {0}")]
    InvalidHeaderValue(#[from] hyper::header::InvalidHeaderValue),
}

impl IntoResponse for KeylometerError {
    type Body = axum::body::Body;
    type BodyError = <Self::Body as axum::body::HttpBody>::Error;

    fn into_response(self) -> Response<Self::Body> {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from(format!("{}", self)))
            .unwrap()
    }
}

async fn deserialize<T>(res: Response<Body>) -> serde_json::Result<Response<T>>
    where for<'de> T: de::Deserialize<'de>,
{
    let (parts, body) = res.into_parts();
    let b = hyper::body::to_bytes(body).await.unwrap();
    let body = serde_json::from_slice(b.borrow())?;
    Ok(Response::from_parts(parts, body))
}

fn serialize<T>(req: Request<T>) -> Result<Request<Body>, KeylometerError>
    where T: ser::Serialize,
{
    let (mut parts, body) = req.into_parts();
    let body = serde_json::to_vec(&body)?;
    parts.headers.insert(hyper::header::CONTENT_TYPE, HeaderValue::from_str("application/json")?);
    Ok(Request::from_parts(parts, Body::from(body)))
}

#[tokio::main]
async fn main() -> Result<(), KeylometerError> {
// Set the RUST_LOG, if it hasn't been explicitly defined
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var(
            "RUST_LOG",
            "keylometer=debug,tower_http=debug",
        )
    }
    tracing_subscriber::fmt::init();

    let matches = App::new("Keylometer")
        .version("0.1.0")
        .author("Julius de Jeu")
        .about("An application that can receive github ssh keys for a user!")
        .arg(Arg::with_name("daemon")
            .short("d")
            .long("daemon")
            .help("Starts in daemon mode"))
        .arg(Arg::with_name("socket")
            .long("socket")
            .takes_value(true)
            .default_value("/var/run/keylometer.sock")
            .help("Sets the socket path to use"))
        .arg(Arg::with_name("config")
            .long("config")
            .short("c")
            .help("Sets the path for the config, only used by the daemon")
            .takes_value(true)
            .default_value("/etc/keylometer/config.yml"))
        .subcommand(SubCommand::with_name("keys")
            .about("Get the github keys configured for a user")
            .arg(Arg::with_name("USERNAME")
                .index(1).help("The name of the user")))
        .get_matches();

    let daemon = matches.is_present("daemon");
    let socket_path = matches.value_of("socket").expect("Socket is missing?");
    if daemon {
        tracing::info!("Running daemon on {}!", socket_path);
        let conf = matches.value_of("config").expect("Config is missing?");
        let f = std::fs::File::open(conf)?;
        let perms = f.metadata()?.permissions();
        let r = std::fs::read(conf).expect("Could not read config file!");
        let mut r: Config = serde_yaml::from_slice(r.borrow())?;
        if perms.mode() & 0o177 != 0 {
            tracing::warn!("Permissions for {} are too loose, they are set to {:o}.", conf, perms.mode() & 777);
            tracing::warn!("Set them to 600 to enable remote updates!");
            r.allow_update = false;
        }


        if r.allow_update {
            tracing::warn!("Autoupdate is enabled!")
        }

        return run_socket(socket_path, r).await;
    } else {
        let client = hyper::Client::unix();
        if let Some(s) = matches.subcommand_matches("keys") {
            let vs = s.value_of("USERNAME").unwrap();
            let url: hyper::http::Uri = hyperlocal::Uri::new(socket_path, "/keys").into();
            let req = Request::post(url).body(vs).unwrap();
            let res: Response<Vec<String>> = deserialize(client.request(serialize(req)?).await?).await?;
            for b in res.body() {
                println!("{}", b)
            }
        }

        Ok(())
    }
}