//! Keeps the asor status lists (step 7) current: each configured list is
//! read from its file or fetched from its `uri`, verified, and stored where
//! the asor verifier looks it up. A failed refresh keeps the list held,
//! which the verifier trusts until its `ttl` or `max_age` runs out.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use visado_chain_asor::{MemoryStatusLists, StatusListError, StatusListVerifier, StatusLists};

/// The largest Status List Token read from a file or an HTTP response, in
/// bytes: the verifier's own default limit.
pub const MAX_TOKEN_SIZE: usize = 1024 * 1024;

/// The media type of a Status List Token in JWT format (§8.1 of the status
/// list draft).
const MEDIA_TYPE: &str = "application/statuslist+jwt";

/// Where one list comes from.
#[derive(Debug, Clone)]
pub enum Source {
    /// A file holding the token, re-read at each refresh.
    File(PathBuf),
    /// An HTTP GET of the list's `uri`.
    Http,
}

/// The configured lists and what refreshing them needs.
pub struct StatusRefresh {
    pub lists: Arc<MemoryStatusLists>,
    pub verifier: StatusListVerifier,
    pub sources: Vec<(String, Source)>,
    pub max_age: i64,
    pub refresh: Duration,
    pub timeout: Duration,
}

impl StatusRefresh {
    /// Loads every file list now, failing on the first that does not verify,
    /// so a bad file stops startup.
    pub fn load_files(&self) -> Result<(), String> {
        for (uri, source) in &self.sources {
            if let Source::File(path) = source {
                let result = read_file(path).and_then(|t| self.verifier.verify(&t, uri, now()));
                self.lists
                    .update(uri, result)
                    .map_err(|e| format!("{}: status list {uri}: {e}", path.display()))?;
            }
        }
        Ok(())
    }

    /// Starts one task per list. Must be called inside the Tokio runtime.
    pub fn spawn(self) -> Result<(), String> {
        let client = client(self.timeout)?;
        let shared = Arc::new(self);
        for index in 0..shared.sources.len() {
            let shared = Arc::clone(&shared);
            let client = client.clone();
            tokio::spawn(async move {
                let (uri, source) = &shared.sources[index];
                loop {
                    shared.refresh_one(&client, uri, source).await;
                    tokio::time::sleep(shared.next(uri)).await;
                }
            });
        }
        Ok(())
    }

    async fn refresh_one(&self, client: &reqwest::Client, uri: &str, source: &Source) {
        let token = match source {
            Source::File(path) => read_file(path),
            Source::Http => fetch(client, uri).await,
        };
        let result = token.and_then(|t| self.verifier.verify(&t, uri, now()));
        match self.lists.update(uri, result) {
            Ok(()) => tracing::debug!(uri, "status list refreshed"),
            Err(e) => tracing::warn!(uri, reason = e.reason(), "status list refresh failed"),
        }
    }

    /// The wait before the next refresh: `refresh`, or half the time the
    /// held list has left before it goes stale if that is sooner, and at
    /// least one second.
    fn next(&self, uri: &str) -> Duration {
        let left = self
            .lists
            .get(uri)
            .ok()
            .map(|list| list.stale_at(self.max_age).saturating_sub(now()) / 2)
            .map_or(self.refresh, |s| {
                Duration::from_secs(u64::try_from(s).unwrap_or(0))
            });
        left.min(self.refresh).max(Duration::from_secs(1))
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

fn read_file(path: &std::path::Path) -> Result<String, StatusListError> {
    use std::io::Read as _;
    let file = std::fs::File::open(path).map_err(|_| StatusListError::Unavailable)?;
    let mut text = String::new();
    file.take(MAX_TOKEN_SIZE as u64 + 1)
        .read_to_string(&mut text)
        .map_err(|_| StatusListError::Unavailable)?;
    if text.len() > MAX_TOKEN_SIZE {
        return Err(StatusListError::TooLarge);
    }
    Ok(text.trim().to_owned())
}

/// A client that follows no redirects: the list's `sub` must equal the
/// configured `uri`, so a list served from elsewhere would not verify, and
/// following one would let the origin point the gate at internal hosts.
fn client(timeout: Duration) -> Result<reqwest::Client, String> {
    // reqwest is built without a bundled crypto provider; as for the PDP
    // client, install ring unless the process already chose one.
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("status list client: {e}"))
}

/// GETs the list at `uri` (§8.1, §8.2): a 2xx response of type
/// `application/statuslist+jwt`, at most [`MAX_TOKEN_SIZE`] bytes.
async fn fetch(client: &reqwest::Client, uri: &str) -> Result<String, StatusListError> {
    let mut response = client
        .get(uri)
        .header(reqwest::header::ACCEPT, MEDIA_TYPE)
        .send()
        .await
        .map_err(|_| StatusListError::Unavailable)?;
    if !response.status().is_success() {
        return Err(StatusListError::Unavailable);
    }
    let media_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .map(str::trim);
    if !media_type.is_some_and(|t| t.eq_ignore_ascii_case(MEDIA_TYPE)) {
        return Err(StatusListError::Malformed(
            "status list response is not application/statuslist+jwt",
        ));
    }
    if response
        .content_length()
        .is_some_and(|len| len > MAX_TOKEN_SIZE as u64)
    {
        return Err(StatusListError::TooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| StatusListError::Unavailable)?
    {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_TOKEN_SIZE {
            return Err(StatusListError::TooLarge);
        }
    }
    String::from_utf8(body)
        .map(|t| t.trim().to_owned())
        .map_err(|_| StatusListError::Malformed("status list response is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::Router;
    use axum::http::header::CONTENT_TYPE;
    use axum::routing::get;
    use visado_chain_asor::StatusListError;

    use super::{MAX_TOKEN_SIZE, client, fetch};

    async fn serve(router: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn fetch_needs_a_status_list_response() {
        let router = Router::new()
            .route(
                "/ok",
                get(|| async { ([(CONTENT_TYPE, "application/statuslist+jwt")], "a.b.c\n") }),
            )
            .route(
                "/json",
                get(|| async { ([(CONTENT_TYPE, "application/json")], "a.b.c") }),
            )
            .route(
                "/big",
                get(|| async {
                    (
                        [(CONTENT_TYPE, "application/statuslist+jwt")],
                        "a".repeat(MAX_TOKEN_SIZE + 1),
                    )
                }),
            )
            .route(
                "/redirect",
                get(|| async {
                    (
                        axum::http::StatusCode::FOUND,
                        [(axum::http::header::LOCATION, "/ok")],
                    )
                }),
            );
        let base = serve(router).await;
        let client = client(Duration::from_secs(2)).unwrap();
        assert_eq!(
            fetch(&client, &format!("{base}/ok")).await.unwrap(),
            "a.b.c"
        );
        assert!(matches!(
            fetch(&client, &format!("{base}/json")).await,
            Err(StatusListError::Malformed(_))
        ));
        assert_eq!(
            fetch(&client, &format!("{base}/big")).await,
            Err(StatusListError::TooLarge)
        );
        assert_eq!(
            fetch(&client, &format!("{base}/missing")).await,
            Err(StatusListError::Unavailable)
        );
        // A redirect is not followed.
        assert_eq!(
            fetch(&client, &format!("{base}/redirect")).await,
            Err(StatusListError::Unavailable)
        );
        assert_eq!(
            fetch(&client, "http://127.0.0.1:9/unreachable").await,
            Err(StatusListError::Unavailable)
        );
    }

    /// A list fetched over HTTP is verified and held; a failed refresh keeps
    /// it, and the next refresh comes before it goes stale.
    #[tokio::test]
    async fn a_failed_refresh_keeps_the_list_held() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        use visado_chain_asor::{MemoryStatusLists, StatusListVerifier, StatusLists, TrustAnchor};
        use visado_testkit::{
            STATUS_LIST_ISSUER, status_list_key, status_list_lst, status_list_token,
        };

        use super::{Source, StatusRefresh, now};

        let up = Arc::new(AtomicBool::new(true));
        let serving = Arc::clone(&up);
        let base = serve(Router::new().route(
            "/list",
            get(move |headers: axum::http::HeaderMap| {
                let up = serving.load(Ordering::SeqCst);
                let host = headers
                    .get(axum::http::header::HOST)
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                async move {
                    let token = status_list_token(
                        &serde_json::json!({ "alg": "Ed25519", "typ": "statuslist+jwt" }),
                        &serde_json::json!({
                            "sub": format!("http://{host}/list"), "iat": now(), "ttl": 40,
                            "status_list": { "bits": 1, "lst": status_list_lst(1, &[1]) },
                        }),
                    );
                    let status = if up {
                        axum::http::StatusCode::OK
                    } else {
                        axum::http::StatusCode::SERVICE_UNAVAILABLE
                    };
                    (
                        status,
                        [(CONTENT_TYPE, "application/statuslist+jwt")],
                        token,
                    )
                }
            }),
        ))
        .await;
        let uri = format!("{base}/list");
        let refresh = StatusRefresh {
            lists: Arc::new(MemoryStatusLists::new()),
            verifier: StatusListVerifier::new(vec![TrustAnchor::new(
                STATUS_LIST_ISSUER,
                status_list_key().verifying_key(),
            )]),
            sources: vec![(uri.clone(), Source::Http)],
            max_age: 300,
            refresh: Duration::from_secs(60),
            timeout: Duration::from_secs(2),
        };
        let client = client(refresh.timeout).unwrap();
        assert_eq!(refresh.next(&uri), Duration::from_secs(60), "nothing held");
        refresh.refresh_one(&client, &uri, &Source::Http).await;
        let held = refresh.lists.get(&uri).unwrap();
        assert_eq!(held.status(0), Some(1));
        assert!(
            refresh.next(&uri) <= Duration::from_secs(20),
            "half the ttl"
        );
        up.store(false, Ordering::SeqCst);
        refresh.refresh_one(&client, &uri, &Source::Http).await;
        assert_eq!(refresh.lists.get(&uri).unwrap(), held);
    }
}
