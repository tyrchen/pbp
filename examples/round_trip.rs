use std::time::SystemTime;

use digest::Digest;
use ed25519_dalek::SigningKey;
use pbp::{KeyFlags, PgpKey, PgpSig, SigType};
use rand::rngs::OsRng;
use sha2::{Sha256, Sha512};

const DATA: &[u8] = b"How will I ever get out of this labyrinth?";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();
    let key = PgpKey::from_dalek::<Sha256, Sha512>(
        &signing_key,
        KeyFlags::NONE,
        timestamp as u32,
        "withoutboats",
    );
    let sig = PgpSig::from_dalek::<Sha256, Sha512>(
        &signing_key,
        DATA,
        key.fingerprint(),
        SigType::BinaryDocument,
        timestamp as u32,
    );
    if sig.verify_dalek::<Sha256, Sha512, _>(&signing_key.verifying_key(), |hasher| {
        hasher.update(DATA);
    }) {
        println!("Verified successfully.");
    } else {
        println!("Could not verify.");
    }

    Ok(())
}
