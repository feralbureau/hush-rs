//! QUIC transport helpers.

use std::sync::Arc;
use thiserror::Error;

pub const DEFAULT_ALPN: &str = "hush/1";

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("transport: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("transport: {0}")]
    Config(String),
}

/// Dial a QUIC connection to addr.
pub async fn dial(
    addr: &str,
    client_tls: Option<rustls::ClientConfig>,
) -> Result<(quinn::Connection, quinn::Endpoint), TransportError> {
    let tls = client_tls.unwrap_or_else(insecure_client_tls);

    let quic_config = quinn::ClientConfig::new(
        Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls)
                .map_err(|e| TransportError::Config(format!("quic config: {}", e)))?
        )
    );

    let endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
        .map_err(|e| TransportError::Config(format!("bind: {}", e)))?;

    let addr: std::net::SocketAddr = addr.parse()
        .map_err(|e| TransportError::Config(format!("addr parse: {}", e)))?;

    let conn = endpoint
        .connect_with(quic_config, addr, DEFAULT_ALPN)
        .map_err(|e| TransportError::Config(format!("connect: {}", e)))?
        .await?;

    Ok((conn, endpoint))
}

/// Create a QUIC server endpoint that listens on addr.
pub fn listen(
    addr: &str,
    server_tls: rustls::ServerConfig,
) -> Result<quinn::Endpoint, TransportError> {
    let quic_config = quinn::ServerConfig::with_crypto(
        Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_tls)
                .map_err(|e| TransportError::Config(format!("quic config: {}", e)))?
        )
    );

    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::clone(&quic_config),
        addr.parse()
            .map_err(|e| TransportError::Config(format!("addr parse: {}", e)))?,
    ).map_err(|e| TransportError::Config(format!("listen: {}", e)))?;

    Ok(endpoint)
}

pub fn insecure_client_tls() -> rustls::ClientConfig {
    

    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(
            Arc::new(SkipVerify),
        )
        .with_no_client_auth()
}

#[derive(Debug)]
struct SkipVerify;

impl rustls::client::danger::ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer,
        _intermediates: &[rustls::pki_types::CertificateDer],
        _server_name: &rustls::pki_types::ServerName,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
