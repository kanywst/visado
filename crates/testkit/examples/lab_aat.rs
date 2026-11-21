//! Prints the headers and body of an MCP `tools/call` for the lab, carrying an
//! AAT chain in which agent-a holds the root and delegates `read_file` on
//! `/data/report.pdf` to agent-b, at the current time. The agents' keys and
//! the WIT are SPIRE WIT-SVIDs, read from `<svid-dir>/<workload>.json` (the
//! output of `spire-agent api fetch wit -output json`), so the chain is bound
//! to the keys SPIRE issued. The root AAT is signed with the fixed demo anchor
//! key.
//!
//! ```text
//! lab_aat <svid-dir> <workload> <tool> <arguments-json> [--root <grants>] [--child <grants>]
//! ```
//!
//! `--root` replaces what the root grants agent-a and `--child` what agent-a
//! delegates to agent-b: JSON objects of tool name to argument constraints, as
//! in `authorization_details`. The attack demos use them to build a child
//! that grants more than its parent.
//!
//! Output: `Name: value` header lines, then `BODY: <json>`.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use visado_testkit::SpireWitSvid;
use wimsey_wpt::WptClaims;

const AUTHORITY: &str = "tools.td.example";

fn svid(dir: &str, workload: &str) -> SpireWitSvid {
    let file = Path::new(dir).join(format!("{workload}.json"));
    let output =
        std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    visado_testkit::spire_wit_svid(&output).unwrap_or_else(|e| panic!("{}: {e}", file.display()))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = || -> ! {
        eprintln!(
            "usage: lab_aat <svid-dir> <workload> <tool> <arguments-json> [--root <grants>] [--child <grants>]"
        );
        std::process::exit(2);
    };
    let (Some(dir), Some(workload), Some(tool), Some(arguments)) =
        (args.first(), args.get(1), args.get(2), args.get(3))
    else {
        usage();
    };
    let arguments: Value = serde_json::from_str(arguments).expect("arguments are JSON");
    let mut root_grants = json!({
        "read_file": { "path": { "constraint_type": "wildcard" } },
        "delete_file": { "path": { "constraint_type": "wildcard" } },
    });
    let mut child_grants = json!({
        "read_file": { "path": { "constraint_type": "one_of", "values": ["/data/report.pdf"] } },
    });
    let mut rest = args[4..].iter();
    while let Some(flag) = rest.next() {
        let grants: Value = match rest.next() {
            Some(text) => serde_json::from_str(text).expect("grants are JSON"),
            None => usage(),
        };
        match flag.as_str() {
            "--root" => root_grants = grants,
            "--child" => child_grants = grants,
            _ => usage(),
        }
    }
    let clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970");
    let now = clock.as_secs();
    let nonce = format!("{}-{}", clock.as_nanos(), std::process::id());

    let agent_a = svid(dir, "agent-a").key;
    let agent_b = svid(dir, "agent-b").key;
    let root = visado_testkit::aat_root(
        &format!("root-{nonce}"),
        &agent_a,
        &root_grants,
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
        &child_grants,
        1,
        3,
        now,
    );

    let SpireWitSvid {
        wit, key: holder, ..
    } = svid(dir, workload);
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
