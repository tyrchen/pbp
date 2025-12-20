//! This library is designed to integrate non-PGP generated and verified keys
//! and signatures with channels that expect PGP data. It specifically only
//! supports the ed25519 signature scheme.
//!
//! Sometimes you want to be able to sign data, and the only reasonable channel
//! to transmit signatures and public keys available to you expects them to be
//! PGP formatted. If you don't want to use a heavyweight dependency like gpg,
//! this library supports only the minimal necessary components of the PGP
//! format to transmit your keys and signatures.
#![deny(missing_docs, missing_debug_implementations)]

#[cfg(feature = "dalek")]
extern crate ed25519_dalek as dalek;

mod ascii_armor;
mod packet;

mod key;
mod sig;

pub use crate::key::PgpKey;
pub use crate::sig::{PgpSig, SigType, SubPacket};

use base64::Engine;

/// An OpenPGP public key fingerprint.
pub type Fingerprint = [u8; 20];
/// An ed25519 signature.
pub type Signature = [u8; 64];

bitflags::bitflags! {
    /// The key flags assigned to this key.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct KeyFlags: u8 {
        /// No key flags.
        const NONE              = 0x00;
        /// The Certify flag.
        const CERTIFY           = 0x01;
        /// The Sign flag.
        const SIGN              = 0x02;
        /// The Encrypt Communication flag.
        const ENCRYPT_COMS      = 0x04;
        /// The Encrypt Storage flag.
        const ENCRYPT_STORAGE   = 0x08;
        /// The Authentication flag.
        const AUTHENTICATION    = 0x20;
    }
}

/// An error returned while attempting to parse a PGP signature or public key.
#[derive(thiserror::Error, Debug)]
pub enum PgpError {
    /// Invalid ASCII armor format
    #[error("Invalid ASCII armor format")]
    InvalidAsciiArmor,
    /// Packet header incorrectly formatted
    #[error("Packet header incorrectly formatted")]
    InvalidPacketHeader,
    /// Unsupported packet length format
    #[error("Unsupported packet length format")]
    UnsupportedPacketLength,
    /// Unsupported form of signature packet
    #[error("Unsupported form of signature packet")]
    UnsupportedSignaturePacket,
    /// First hashed subpacket of signature must be the key fingerprint
    #[error("First hashed subpacket of signature must be the key fingerprint")]
    MissingFingerprintSubpacket,
    /// Unsupported form of public key packet
    #[error("Unsupported form of public key packet")]
    UnsupportedPublicKeyPacket,
}

// Helper for writing base64 data
struct Base64<'a>(&'a [u8]);

impl std::fmt::Debug for Base64<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use base64::engine::general_purpose::STANDARD;
        f.write_str(&STANDARD.encode(self.0))
    }
}
