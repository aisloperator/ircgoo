//! TLS client configuration: system CAs and/or user-trusted certificates, optional client cert.

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Clone, Debug, Default)]
pub struct TlsSettings {
    pub use_system_cas: bool,
    pub trusted_certs: Vec<PathBuf>,
    /// PEM file with certificate chain and private key (SASL EXTERNAL / CertFP).
    pub client_cert: Option<PathBuf>,
}

/// Accepts a chain valid against the root store, or a leaf certificate that the user
/// explicitly trusts (useful for self-signed bouncers).
#[derive(Debug)]
struct GooVerifier {
    webpki: Option<Arc<WebPkiServerVerifier>>,
    pinned: Vec<CertificateDer<'static>>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for GooVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.pinned.iter().any(|c| c.as_ref() == end_entity.as_ref()) {
            return Ok(ServerCertVerified::assertion());
        }
        match &self.webpki {
            Some(v) => v.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now),
            None => Err(rustls::Error::General(
                "server certificate is not trusted (no trusted certificates configured)".into(),
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

pub fn client_config(s: &TlsSettings) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    if s.use_system_cas {
        let res = rustls_native_certs::load_native_certs();
        roots.add_parsable_certificates(res.certs);
    }
    let mut pinned = Vec::new();
    for path in &s.trusted_certs {
        let iter = CertificateDer::pem_file_iter(path)
            .map_err(|e| format!("Cannot read trusted certificate {}: {e}", path.display()))?;
        for cert in iter {
            let cert = cert.map_err(|e| format!("Bad certificate in {}: {e}", path.display()))?;
            // Works as a CA if it is one; otherwise it is still accepted as an exact match.
            let _ = roots.add(cert.clone());
            pinned.push(cert);
        }
    }
    let webpki = if roots.is_empty() {
        None
    } else {
        Some(
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .map_err(|e| format!("TLS setup failed: {e}"))?,
        )
    };
    let verifier = Arc::new(GooVerifier {
        webpki,
        pinned,
        provider: provider.clone(),
    });
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS setup failed: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let config = match &s.client_cert {
        Some(path) => {
            let chain: Vec<CertificateDer<'static>> =
                CertificateDer::pem_file_iter(path)
                    .and_then(|it| it.collect())
                    .map_err(|e| format!("Cannot read client certificate {}: {e}", path.display()))?;
            if chain.is_empty() {
                return Err(format!("No certificate found in {}", path.display()));
            }
            let key = PrivateKeyDer::from_pem_file(path)
                .map_err(|e| format!("Cannot read private key from {}: {e}", path.display()))?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|e| format!("Client certificate: {e}"))?
        }
        None => builder.with_no_client_auth(),
    };
    Ok(Arc::new(config))
}
