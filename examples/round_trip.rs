use digest::Update;
use ed25519_dalek::Keypair;
use pbp::{KeyFlags, PgpKey, PgpSig, SigType};
use rand::rngs::OsRng;
use sha2::{Sha256, Sha512};

const DATA: &[u8] = b"How will I ever get out of this labyrinth?";

fn main() {
    let mut csprng = OsRng {};
    let keypair = Keypair::generate(&mut csprng);

    let key = PgpKey::from_dalek::<Sha256, Sha512>(&keypair, KeyFlags::SIGN, 0, "withoutboats");
    let sig = PgpSig::from_dalek::<Sha256, Sha512>(
        &keypair,
        DATA,
        key.fingerprint(),
        SigType::BinaryDocument,
        0,
    );
    if sig.verify_dalek::<Sha256, Sha512, _>(&keypair.public, |hasher| hasher.update(DATA)) {
        println!("Verified successfully.");
    } else {
        println!("Could not verify.");
    }
}
