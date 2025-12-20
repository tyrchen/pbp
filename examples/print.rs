use std::time::SystemTime;

use ed25519_dalek::SigningKey;
use pbp::{KeyFlags, PgpKey};
use rand::rngs::OsRng;
use sha2::{Sha256, Sha512};

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
    println!("{}", key);

    Ok(())
}
