use std::io::{self, BufRead};

use pbp::PgpSig;

fn main() {
    let stdin = io::stdin();
    let mut stdin = stdin.lock();

    let mut armor = String::new();

    let mut in_armor = false;

    loop {
        let mut buf = String::new();
        stdin.read_line(&mut buf).unwrap();
        if buf.trim().starts_with("-----") && buf.trim().ends_with("-----") {
            armor.push_str(&buf);
            if in_armor {
                break;
            } else {
                in_armor = true;
            }
        } else if in_armor {
            armor.push_str(&buf);
        }
    }

    if PgpSig::from_ascii_armor(&armor).ok().is_some() {
        println!("Valid PGP Signature");
    }
}
