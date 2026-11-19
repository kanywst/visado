//! Prints request headers for the lab in `deploy/lab`, one `Name: value` per
//! line, at the current time. The WIT and the key that signs the WPT are a
//! SPIRE WIT-SVID, read from `<svid-dir>/<workload>.json` (the output of
//! `spire-agent api fetch wit -output json`). User tokens are signed with the
//! fixed demo keys.
//!
//! ```text
//! lab_headers <svid-dir> <workload> <path> [--user <sub> <scope>] [--txn <token>]
//! ```

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use wimsey_wpt::WptClaims;

const AUTHORITY: &str = "tools.td.example";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(dir), Some(workload), Some(path)) = (args.first(), args.get(1), args.get(2)) else {
        eprintln!(
            "usage: lab_headers <svid-dir> <workload> <path> [--user <sub> <scope>] [--txn <token>]"
        );
        std::process::exit(2);
    };
    let mut user = None;
    let mut txn = None;
    let mut rest = args[3..].iter();
    while let Some(flag) = rest.next() {
        match flag.as_str() {
            "--user" => user = Some((rest.next().cloned(), rest.next().cloned())),
            "--txn" => txn = rest.next().cloned(),
            other => {
                eprintln!("unknown argument {other}");
                std::process::exit(2);
            }
        }
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs();

    let file = Path::new(dir).join(format!("{workload}.json"));
    let output =
        std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    let svid = visado_testkit::spire_wit_svid(&output)
        .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    let (wit, pop) = (svid.wit, svid.key);

    let user_token = user.map(|(sub, scope)| {
        let claims = json!({
            "iss": visado_testkit::OAUTH_ISSUER,
            "sub": sub.unwrap_or_else(|| "alice".into()),
            "aud": format!("http://{AUTHORITY}"),
            "client_id": workload,
            "scope": scope.unwrap_or_default(),
            "iat": now,
            "exp": now + 300,
        });
        visado_testkit::signed_access_token(&claims)
    });

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_nanos();
    let jti = URL_SAFE_NO_PAD.encode(nanos.to_be_bytes()) + &std::process::id().to_string();
    let wpt = wimsey_wpt::issue(
        &WptClaims {
            aud: format!("http://{AUTHORITY}{path}"),
            exp: now + 30,
            jti,
            wth: wimsey_wpt::wit_thumbprint(&wit),
            tth: txn.as_deref().map(wimsey_wpt::txn_token_thumbprint),
            oth: user_token.as_deref().map(|t| {
                std::iter::once(wimsey_wpt::other_token_entry("x-user-token", t)).collect()
            }),
        },
        &pop,
    )
    .expect("wpt");

    println!("Workload-Identity-Token: {wit}");
    println!("Authorization: WPT {wpt}");
    if let Some(token) = user_token {
        println!("X-User-Token: {token}");
    }
    if let Some(token) = txn {
        println!("Txn-Token: {token}");
    }
}
