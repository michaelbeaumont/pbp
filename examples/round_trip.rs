extern crate ed25519_dalek as dalek;
extern crate pbp;
extern crate rand;
extern crate sha2;

use dalek::Keypair;
use pbp::{KeyFlags, PgpKey, PgpSig, SigType};
use rand::OsRng;
use sha2::{Sha256, Sha512};

const DATA: &[u8] = b"How will I ever get out of this labyrinth?";

fn main() {
    let mut cspring = OsRng::new().unwrap();
    let keypair = Keypair::generate::<Sha512>(&mut cspring);

    let key = PgpKey::from_dalek::<Sha256, Sha512>(&keypair, KeyFlags::SIGN, "withoutboats");
    let sig = PgpSig::from_dalek::<Sha256, Sha512>(
        &keypair,
        DATA,
        key.fingerprint(),
        SigType::BinaryDocument,
    );
    if sig.verify_dalek::<Sha256, Sha512>(DATA, &keypair.public) {
        println!("Verified successfully.");
    } else {
        println!("Could not verify.");
    }
}
