//! Workloads that authenticate to the proxy with an X.509-SVID.

use visado_credentials::{Authenticated, Authenticator, Method, RequestView, X509Bundle};
use visado_testkit::{
    NOW, TRUST_DOMAIN, certificate_pem, envoy_peer_certificate, pop_key, wic, wic_at, workload_ca,
};
use wimsey_jose::SigningKey;

const AGENT: &str = "spiffe://td.example/agent-a";

fn authenticator() -> Authenticator {
    let ca = certificate_pem(workload_ca().certificate_der());
    Authenticator::new().with_x509_bundle(X509Bundle::from_pem(TRUST_DOMAIN, &ca).unwrap())
}

fn run(
    auth: &Authenticator,
    certificate: Option<&str>,
    headers: &[(&str, &str)],
) -> Result<Authenticated, String> {
    let headers: Vec<(String, String)> = headers
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect();
    let view = RequestView {
        method: "GET",
        scheme: "https",
        authority: "tools.td.example",
        path: "/mcp",
        headers: &headers,
        body: None,
        peer_certificate: certificate,
    };
    auth.authenticate(&view, NOW)
        .map_err(|e| e.code().to_owned())
}

#[test]
fn a_certificate_from_the_trust_domain_ca_authenticates_the_workload() {
    let auth = authenticator();
    let key = pop_key(1);
    let cert = envoy_peer_certificate(&wic(AGENT, &key.verifying_key()));
    let ok = run(&auth, Some(&cert), &[]).unwrap();
    assert_eq!(ok.caller, AGENT);
    assert_eq!(ok.method, Method::Mtls);
    assert!(ok.user.is_none());
    assert_eq!(
        ok.proof_key.unwrap().to_raw_bytes(),
        key.verifying_key().to_raw_bytes()
    );

    // A P-256 workload key is a proof key too.
    let p256 = SigningKey::from_p256_scalar(&[7; 32]).unwrap();
    let cert = envoy_peer_certificate(&wic(AGENT, &p256.verifying_key()));
    let ok = run(&auth, Some(&cert), &[]).unwrap();
    assert_eq!(
        ok.proof_key.unwrap().to_raw_bytes(),
        p256.verifying_key().to_raw_bytes()
    );
}

#[test]
fn rejections_have_reason_codes() {
    let auth = authenticator();
    let key = pop_key(1).verifying_key();
    let other_ca =
        wimsey_mtls::WorkloadCa::from_ed25519(&pop_key(0x99), NOW - 86_400, NOW + 86_400).unwrap();
    let foreign_issuer = other_ca
        .issue(
            &wimsey_identifier::WorkloadIdentifier::parse(AGENT).unwrap(),
            &key,
            NOW - 60,
            NOW + 60,
        )
        .unwrap();
    let pem_two = {
        let one = certificate_pem(&wic(AGENT, &key));
        format!("{one}{one}")
    };

    let cases: Vec<(&str, String, &str)> = vec![
        (
            "expired",
            envoy_peer_certificate(&wic_at(AGENT, &key, NOW - 7200, NOW - 3600)),
            "mtls.invalid",
        ),
        (
            "not yet valid",
            envoy_peer_certificate(&wic_at(AGENT, &key, NOW + 3600, NOW + 7200)),
            "mtls.invalid",
        ),
        (
            "issued by another CA",
            envoy_peer_certificate(&foreign_issuer),
            "mtls.invalid",
        ),
        (
            "another trust domain",
            envoy_peer_certificate(&wic("spiffe://other.example/agent-x", &key)),
            "mtls.untrusted_domain",
        ),
        ("a chain", pem_two, "mtls.invalid"),
        ("not PEM", "garbage".into(), "mtls.invalid"),
        ("bad escape", "%zz".into(), "mtls.invalid"),
        ("too large", "a".repeat(20_000), "credential.too_large"),
    ];
    for (name, cert, code) in cases {
        assert_eq!(run(&auth, Some(&cert), &[]).unwrap_err(), code, "{name}");
    }

    let cert = envoy_peer_certificate(&wic(AGENT, &key));
    assert_eq!(
        run(&auth, Some(&cert), &[("x-user-token", "anything")]).unwrap_err(),
        "credential.unbound_user_token"
    );
}

#[test]
fn the_certificate_is_used_only_when_configured_and_nothing_else_is_sent() {
    let cert = envoy_peer_certificate(&wic(AGENT, &pop_key(1).verifying_key()));
    assert_eq!(
        run(&Authenticator::new(), Some(&cert), &[]).unwrap_err(),
        "credential.missing"
    );
    // A credential header takes precedence over the transport.
    assert_eq!(
        run(
            &authenticator(),
            Some(&cert),
            &[("authorization", "Bearer x")]
        )
        .unwrap_err(),
        "token.invalid"
    );
}

#[test]
fn a_bundle_is_one_certificate() {
    assert!(X509Bundle::from_pem(TRUST_DOMAIN, "garbage").is_err());
    let one = certificate_pem(workload_ca().certificate_der());
    assert!(X509Bundle::from_pem(TRUST_DOMAIN, &format!("{one}{one}")).is_err());
    assert!(X509Bundle::from_der(TRUST_DOMAIN, vec![0x30, 0x00]).is_err());
}
