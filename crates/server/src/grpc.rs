//! The gRPC listener's server, with TLS when `[grpc_tls]` is set.

use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use crate::config::GrpcTls;

/// A server builder, with TLS (and client certificates, when a client CA is
/// set) from `tls`. A certificate, key or CA that does not load fails here,
/// at startup.
pub fn server(tls: Option<&GrpcTls>) -> Result<Server, String> {
    let builder = Server::builder();
    let Some(tls) = tls else {
        return Ok(builder);
    };
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut config = ServerTlsConfig::new().identity(Identity::from_pem(&tls.cert, &tls.key));
    if let Some(ca) = &tls.client_ca {
        config = config.client_ca_root(Certificate::from_pem(ca));
    }
    builder
        .tls_config(config)
        .map_err(|e| format!("grpc_tls: {e}"))
}

#[cfg(test)]
mod tests {
    use envoy_types::ext_authz::v3::pb::{
        Authorization, AuthorizationServer, CheckRequest, CheckResponse,
    };
    use envoy_types::pb::envoy::service::auth::v3::authorization_client::AuthorizationClient;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

    use super::server;
    use crate::config::GrpcTls;

    /// Answers every check with an empty response.
    struct Stub;

    #[tonic::async_trait]
    impl Authorization for Stub {
        async fn check(
            &self,
            _: tonic::Request<CheckRequest>,
        ) -> Result<tonic::Response<CheckResponse>, tonic::Status> {
            Ok(tonic::Response::new(CheckResponse::default()))
        }
    }

    fn pem(label: &str, der: &[u8]) -> Vec<u8> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let encoded = STANDARD.encode(der);
        let mut pem = format!("-----BEGIN {label}-----\n");
        for line in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END ");
        pem.push_str(label);
        pem.push_str("-----\n");
        pem.into_bytes()
    }

    /// A CA, and certificates it issues as PEM (certificate, key).
    struct Ca {
        cert: Vec<u8>,
        issuer: Issuer<'static, KeyPair>,
    }

    impl Ca {
        fn new() -> Self {
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let cert = params.self_signed(&key).unwrap();
            Self {
                cert: pem("CERTIFICATE", cert.der()),
                issuer: Issuer::new(params, key),
            }
        }

        fn issue(&self, name: &str) -> (Vec<u8>, Vec<u8>) {
            let key = KeyPair::generate().unwrap();
            let cert = CertificateParams::new(vec![name.to_owned()])
                .unwrap()
                .signed_by(&key, &self.issuer)
                .unwrap();
            (
                pem("CERTIFICATE", cert.der()),
                pem("PRIVATE KEY", &key.serialize_der()),
            )
        }
    }

    /// Serves the stub on a loopback port with `tls`; returns the port.
    async fn serve(tls: Option<&GrpcTls>) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let router = server(tls)
            .unwrap()
            .add_service(AuthorizationServer::new(Stub));
        tokio::spawn(
            router.serve_with_incoming(tonic::transport::server::TcpIncoming::from(listener)),
        );
        port
    }

    /// Calls Check over TLS trusting `ca`, presenting `identity` if given.
    async fn check(
        port: u16,
        ca: &[u8],
        identity: Option<(Vec<u8>, Vec<u8>)>,
    ) -> Result<(), String> {
        let mut tls = ClientTlsConfig::new()
            .ca_certificate(tonic::transport::Certificate::from_pem(ca))
            .domain_name("localhost");
        if let Some((cert, key)) = identity {
            tls = tls.identity(tonic::transport::Identity::from_pem(cert, key));
        }
        let channel = Endpoint::from_shared(format!("https://localhost:{port}"))
            .unwrap()
            .tls_config(tls)
            .map_err(|e| e.to_string())?
            .connect()
            .await
            .map_err(|e| format!("{e:?}"))?;
        call(channel).await
    }

    async fn call(channel: Channel) -> Result<(), String> {
        AuthorizationClient::new(channel)
            .check(CheckRequest::default())
            .await
            .map(|_| ())
            .map_err(|e| format!("{e:?}"))
    }

    async fn plaintext(port: u16) -> Result<(), String> {
        let channel = Endpoint::from_shared(format!("http://127.0.0.1:{port}"))
            .unwrap()
            .connect()
            .await
            .map_err(|e| format!("{e:?}"))?;
        call(channel).await
    }

    #[tokio::test]
    async fn tls_without_a_client_ca_serves_any_tls_client() {
        let ca = Ca::new();
        let (cert, key) = ca.issue("localhost");
        let tls = GrpcTls {
            cert,
            key,
            client_ca: None,
        };
        let port = serve(Some(&tls)).await;
        check(port, &ca.cert, None).await.unwrap();
        assert!(plaintext(port).await.is_err());
    }

    #[tokio::test]
    async fn a_client_ca_refuses_clients_without_its_certificate() {
        let server_ca = Ca::new();
        let proxy_ca = Ca::new();
        let (cert, key) = server_ca.issue("localhost");
        let tls = GrpcTls {
            cert,
            key,
            client_ca: Some(proxy_ca.cert.clone()),
        };
        let port = serve(Some(&tls)).await;
        check(port, &server_ca.cert, Some(proxy_ca.issue("envoy")))
            .await
            .unwrap();
        assert!(check(port, &server_ca.cert, None).await.is_err());
        // A certificate from another CA.
        assert!(
            check(port, &server_ca.cert, Some(Ca::new().issue("envoy")))
                .await
                .is_err()
        );
        assert!(plaintext(port).await.is_err());
    }

    #[tokio::test]
    async fn without_tls_the_listener_is_plaintext() {
        let port = serve(None).await;
        plaintext(port).await.unwrap();
    }

    #[test]
    fn bad_tls_material_fails_at_startup() {
        let ca = Ca::new();
        let (cert, key) = ca.issue("localhost");
        let bad = |cert: &[u8], key: &[u8], client_ca: Option<&[u8]>| {
            server(Some(&GrpcTls {
                cert: cert.to_vec(),
                key: key.to_vec(),
                client_ca: client_ca.map(<[u8]>::to_vec),
            }))
            .is_err()
        };
        assert!(!bad(&cert, &key, None));
        assert!(bad(b"not a certificate", &key, None));
        assert!(bad(&cert, b"not a key", None));
        assert!(bad(&cert, &key, Some(b"not a certificate")));
    }
}
