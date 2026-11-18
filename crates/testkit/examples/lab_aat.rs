//! Prints the headers and body of an MCP `tools/call` for the lab, carrying an
//! AAT chain in which agent-a holds the root and delegates `read_file` on
//! `/data/report.pdf` to agent-b. Signed with the fixed demo keys at the
//! current time.
//!
//! ```text
//! lab_aat <workload> <tool> <arguments-json>
//! ```
//!
//! Output: `Name: value` header lines, then `BODY: <json>`.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use wimsey_identifier::WorkloadIdentifier;
use wimsey_jose::{Jwk, SigningKey};
use wimsey_wit::{Confirmation, WitClaims};
use wimsey_wpt::WptClaims;

const AUTHORITY: &str = "tools.td.example";

fn key_for(workload: &str) -> SigningKey {
    let seed = workload
        .bytes()
        .fold(7u8, |a, b| a.wrapping_mul(31).wrapping_add(b));
    visado_testkit::pop_key(seed)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(workload), Some(tool), Some(arguments)) = (args.first(), args.get(1), args.get(2))
    else {
        eprintln!("usage: lab_aat <workload> <tool> <arguments-json>");
        std::process::exit(2);
    };
    let arguments: Value = serde_json::from_str(arguments).expect("arguments are JSON");
    let clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970");
    let now = clock.as_secs();
    let nonce = format!("{}-{}", clock.as_nanos(), std::process::id());

    let agent_a = key_for("agent-a");
    let agent_b = key_for("agent-b");
    let root = visado_testkit::aat_root(
        &format!("root-{nonce}"),
        &agent_a,
        &json!({
            "read_file": { "path": { "constraint_type": "wildcard" } },
            "delete_file": { "path": { "constraint_type": "wildcard" } },
        }),
        now,
        3,
        &format!("http://{AUTHORITY}"),
    );
    let child_jti = format!("child-{nonce}");
    let child = visado_testkit::aat_child(
        &child_jti,
        &root,
        &agent_a,
        &agent_b,
        &json!({
            "read_file": { "path": { "constraint_type": "one_of", "values": ["/data/report.pdf"] } },
        }),
        1,
        3,
        now,
    );

    let holder = key_for(workload);
    let pop = visado_testkit::aat_pop(
        &format!("pop-{nonce}"),
        &child,
        &child_jti,
        &holder,
        tool,
        &arguments,
        &format!("http://{AUTHORITY}"),
        now,
    );
    let wit = wimsey_wit::issue(
        &WitClaims {
            iss: None,
            sub: WorkloadIdentifier::parse(&format!("spiffe://td.example/{workload}"))
                .expect("valid workload name"),
            iat: Some(now),
            exp: now + 300,
            jti: None,
            cnf: Confirmation {
                jwk: Jwk::from_verifying_key(&holder.verifying_key()),
            },
        },
        Some("wit-1"),
        &visado_testkit::wit_issuer_key(),
    )
    .expect("wit");
    let wpt = wimsey_wpt::issue(
        &WptClaims {
            aud: format!("http://{AUTHORITY}/mcp"),
            exp: now + 30,
            jti: format!("wpt-{nonce}"),
            wth: wimsey_wpt::wit_thumbprint(&wit),
            tth: None,
            oth: None,
        },
        &holder,
    )
    .expect("wpt");

    println!("Workload-Identity-Token: {wit}");
    println!("Authorization: WPT {wpt}");
    println!("AAT-Chain: {root},{child}");
    println!("AAT-PoP: {pop}");
    println!("Content-Type: application/json");
    println!(
        "BODY: {}",
        json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": tool, "arguments": arguments } })
    );
}
