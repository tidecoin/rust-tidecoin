use tidecoin::secp256k1::rand;
use tidecoin::{Address, CompressedPublicKey, Network};

/// Generate a P2WPKH (pay-to-witness-public-key-hash) address and print it.
fn main() {
    // Generate secp256k1 public and private key pair.
    let (_secret_key, public_key) = secp256k1::generate_keypair(&mut rand::rng());

    // Create a compressed Tidecoin public key from the secp256k1 public key.
    let public_key = CompressedPublicKey::from_secp(public_key);

    // Create a Tidecoin P2WPKH address.
    let address = Address::p2wpkh(public_key, Network::Tidecoin);

    println!("Address: {address}");
}
