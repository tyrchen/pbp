# pbp - Pretty Bad Protocol

A Rust library for generating OpenPGP-formatted datagrams from ed25519 keys and signatures. This crate bridges non-PGP systems to transport mediums that expect PGP data, without requiring heavyweight cryptography dependencies.

## Features

- Generate OpenPGP public key blocks from ed25519 keys
- Create and verify OpenPGP signatures
- Parse ASCII-armored PGP keys and signatures
- Agnostic to your ed25519 implementation - bring your own signing function
- Optional integration with [ed25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)
- RFC 4880 compliant ASCII armoring with CRC-24 checksums

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
pbp = "0.7"
```

With ed25519-dalek integration:

```toml
[dependencies]
pbp = { version = "0.7", features = ["dalek"] }
```

## Usage

### Generic API (Bring Your Own Signing)

The library is agnostic about your ed25519 implementation. Provide a closure that signs data:

```rust
use pbp::{KeyFlags, PgpKey};
use sha2::Sha256;

let pgp_key = PgpKey::new::<Sha256, _>(
    &public_key_bytes,      // 32-byte ed25519 public key
    KeyFlags::SIGN,
    timestamp,              // Unix timestamp
    "user@example.com",
    |data| sign(data),      // Your signing function returning 64-byte signature
);

// Print ASCII-armored public key
println!("{}", pgp_key);
```

Create and verify signatures:

```rust
use pbp::{PgpSig, SigType};
use sha2::Sha256;

// Create a signature
let sig = PgpSig::new::<Sha256, _>(
    data,
    fingerprint,
    SigType::BinaryDocument,
    timestamp,
    &[],                    // Optional subpackets
    |hash_data| sign(hash_data),
);

// Verify a signature
let valid = sig.verify::<Sha256, _, _>(
    |hasher| hasher.update(data),
    |hash, sig| verify(&hash, sig),
);
```

### With ed25519-dalek

Enable the `dalek` feature for convenient integration:

```rust
use ed25519_dalek::SigningKey;
use pbp::{KeyFlags, PgpKey, PgpSig, SigType};
use rand::rngs::OsRng;
use sha2::{Sha256, Sha512};

// Generate a key
let signing_key = SigningKey::generate(&mut OsRng);
let timestamp = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_secs() as u32;

// Create a PGP public key
let key = PgpKey::from_dalek::<Sha256, Sha512>(
    &signing_key,
    KeyFlags::SIGN | KeyFlags::CERTIFY,
    timestamp,
    "user@example.com",
);

println!("{}", key);

// Sign some data
let data = b"Hello, world!";
let sig = PgpSig::from_dalek::<Sha256, Sha512>(
    &signing_key,
    data,
    key.fingerprint(),
    SigType::BinaryDocument,
    timestamp,
);

// Verify the signature
let valid = sig.verify_dalek::<Sha256, Sha512, _>(
    &signing_key.verifying_key(),
    |hasher| hasher.update(data),
);
```

### Parsing Existing Keys and Signatures

```rust
use pbp::{PgpKey, PgpSig};

// Parse ASCII-armored key
let key = PgpKey::from_ascii_armor(armored_key_str)?;
let public_key_bytes = key.key_data();
let fingerprint = key.fingerprint();

// Parse ASCII-armored signature
let sig = PgpSig::from_ascii_armor(armored_sig_str)?;
let signature_bytes = sig.signature();
let sig_type = sig.sig_type();

// With dalek feature: convert to dalek types
let verifying_key = key.to_dalek()?;
let dalek_sig = sig.to_dalek();
```

## API Overview

### Types

| Type | Description |
|------|-------------|
| `PgpKey` | An OpenPGP-formatted ed25519 public key |
| `PgpSig` | An OpenPGP-formatted ed25519 signature |
| `SigType` | Signature types (BinaryDocument, TextDocument, etc.) |
| `KeyFlags` | Key capability flags (SIGN, CERTIFY, ENCRYPT_*, etc.) |
| `SubPacket` | Subpacket for including in signatures |
| `Fingerprint` | 20-byte OpenPGP fingerprint (`[u8; 20]`) |
| `Signature` | 64-byte ed25519 signature (`[u8; 64]`) |
| `PgpError` | Error type for parsing operations |

### KeyFlags

```rust
KeyFlags::CERTIFY         // Can certify other keys
KeyFlags::SIGN            // Can create signatures
KeyFlags::ENCRYPT_COMS    // Can encrypt communications
KeyFlags::ENCRYPT_STORAGE // Can encrypt storage
KeyFlags::AUTHENTICATION  // Can authenticate
```

### SigType

```rust
SigType::BinaryDocument       // 0x00 - Sign binary data
SigType::TextDocument         // 0x01 - Sign text data
SigType::Standalone           // 0x02
SigType::GenericCertification // 0x10
SigType::PositiveCertification // 0x13 - Self-signature on keys
// ... and more
```

## Examples

Run the examples with:

```sh
# Generate and print an ASCII-armored public key
cargo run --features dalek --example print

# Parse a signature from stdin
cargo run --features dalek --example read_sig

# Full round-trip: generate key, sign data, verify
cargo run --features dalek --example round_trip

# Verify a signature from files
cargo run --features dalek --example verify_sig
```

## Implementation Notes

- Uses RFC 4880 OpenPGP specification
- Supports only ed25519 keys (algorithm ID 22, EdDSA)
- SHA-256 for signature hashing, SHA-1 for fingerprint computation
- Version 4 signature packets
- Old-style packet headers with two-byte length

## Credits

Thanks to isis lovecruft and Henry de Valence for assistance with the dalek API and understanding the OpenPGP specification.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
