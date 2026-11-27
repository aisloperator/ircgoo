//! TLS client configuration: system CAs and/or user-trusted certificates, optional client cert.

use rustls::CertificateError;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Default)]
pub struct TlsSettings {
    pub use_system_cas: bool,
    pub trusted_certs: Vec<PathBuf>,
    /// PEM file with certificate chain and private key (SASL EXTERNAL / CertFP).
    pub client_cert: Option<PathBuf>,
    /// DER server certificates that the user accepted when prompted. Trusted exactly.
    pub accepted_certs: Vec<Vec<u8>>,
}

/// A server certificate that was refused for a reason the user may override.
#[derive(Clone, Debug)]
pub struct CertRejection {
    /// Why it was refused, as a sentence fragment ("it is not signed by …").
    pub reason: String,
    /// DER of the server's certificate followed by any intermediates it sent.
    pub chain: Vec<Vec<u8>>,
}

/// Where the verifier leaves an overridable rejection for the connection to report.
pub type RejectionSlot = Arc<Mutex<Option<CertRejection>>>;

/// The user-facing reason for an error that trusting the exact certificate can override.
fn overridable_reason(e: &rustls::Error) -> Option<&'static str> {
    let rustls::Error::InvalidCertificate(ce) = e else {
        return None;
    };
    Some(match ce {
        CertificateError::UnknownIssuer => "it is not signed by a certificate authority that IrcGoo trusts",
        CertificateError::Expired | CertificateError::ExpiredContext { .. } => "it has expired",
        CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => "it is not valid yet",
        CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => {
            "it was issued for a different host name"
        }
        CertificateError::Other(other) => match other.0.downcast_ref::<webpki::Error>()? {
            // Typical of self-signed certificates, which OpenSSL marks as CAs by default.
            webpki::Error::CaUsedAsEndEntity => {
                "it is a self-signed certificate, not one from a certificate authority that IrcGoo trusts"
            }
            webpki::Error::UnsupportedCertVersion => "it is an old-style (version 1) certificate",
            _ => return None,
        },
        _ => return None,
    })
}

/// Accepts a chain valid against the root store, or a leaf certificate that the user
/// explicitly trusts (useful for self-signed bouncers).
#[derive(Debug)]
struct GooVerifier {
    webpki: Option<Arc<WebPkiServerVerifier>>,
    pinned: Vec<CertificateDer<'static>>,
    provider: Arc<CryptoProvider>,
    rejection: RejectionSlot,
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
        let (res, reason) = match &self.webpki {
            Some(v) => {
                let res = v.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now);
                let reason = res.as_ref().err().and_then(overridable_reason);
                (res, reason)
            }
            None => (
                Err(rustls::Error::General(
                    "server certificate is not trusted (no trusted certificates configured)".into(),
                )),
                Some("no certificate authorities are trusted for this network"),
            ),
        };
        if let Some(reason) = reason {
            let chain = std::iter::once(end_entity)
                .chain(intermediates)
                .map(|c| c.as_ref().to_vec())
                .collect();
            *self.rejection.lock().unwrap() = Some(CertRejection {
                reason: reason.into(),
                chain,
            });
        }
        res
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

/// The client configuration, and the slot where an overridable rejection of the server's
/// certificate will be left.
pub fn client_config(s: &TlsSettings) -> Result<(Arc<ClientConfig>, RejectionSlot), String> {
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
    pinned.extend(s.accepted_certs.iter().map(|c| CertificateDer::from(c.clone())));
    let webpki = if roots.is_empty() {
        None
    } else {
        Some(
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .map_err(|e| format!("TLS setup failed: {e}"))?,
        )
    };
    let rejection = RejectionSlot::default();
    let verifier = Arc::new(GooVerifier {
        webpki,
        pinned,
        provider: provider.clone(),
        rejection: rejection.clone(),
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
    Ok((Arc::new(config), rejection))
}
