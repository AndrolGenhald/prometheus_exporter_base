#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Authorization {
    None,
    Basic(String),
}

impl Default for Authorization {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TlsOptions {
    /// Path to file containing PEM encoded certificate chain.
    pub certificate_chain_file: String,
    /// Path to file containing private key.
    pub key_file: String,
    /// Path to file containing a CA certificate for client certificates.
    pub client_certificate_ca_file: Option<String>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ServerOptions {
    pub addr: SocketAddr,
    #[cfg_attr(feature = "serde", serde(default))]
    pub authorization: Authorization,
    #[cfg_attr(feature = "serde", serde(default))]
    pub tls_options: Option<TlsOptions>,
}
