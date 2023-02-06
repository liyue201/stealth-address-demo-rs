use std::ops::Add;
use std::str::FromStr;

use ethereum_types::H160;
use num_bigint::BigUint;
use num_integer::Integer;
use secp256k1::{
    constants::{CURVE_ORDER, GENERATOR_X},
    PublicKey, Secp256k1, SecretKey,
};
use sha3::{Digest, Keccak256};

#[allow(non_snake_case)]
fn main() {
    let secp = Secp256k1::new();

    // 1.
    // Bob generates a key m, and computes M = G * m,
    // where G is a commonly-agreed generator point for the elliptic curve.
    // The stealth meta-address is an encoding of M.

    let m = SecretKey::from_str("3b3b08bba24858f7ab8b302428379198e521359b19784a40aeb4daddf4ad911c").unwrap();
    let M = PublicKey::from_secret_key(&secp, &m);

    println!("m: {:?}", hex::encode(m.secret_bytes()));
    println!("M: {:?}", hex::encode(M.serialize()));

    // 2.
    // Alice generates an ephemeral key r, and publishes the ephemeral public key R
    // = G * r.
    let r = SecretKey::from_str("9d23679323734fdf371017048b4a73cf160566a0ccd69fa087299888d9fbc59f").unwrap();
    let R = PublicKey::from_secret_key(&secp, &r);

    println!("r: {:?}", hex::encode(r.secret_bytes()));
    println!("R: {:?}", hex::encode(R.serialize()));

    // 3.
    // Alice can compute a shared secret S = M * r, and Bob can compute the same
    // shared secret S = m * R.

    let scalar = secp256k1::Scalar::from_be_bytes(r.secret_bytes()).unwrap();
    let S = M.mul_tweak(&secp, &scalar).unwrap();

    let scalar = secp256k1::Scalar::from_be_bytes(m.secret_bytes()).unwrap();
    let S2 = R.mul_tweak(&secp, &scalar).unwrap();

    println!("S : {:?}", hex::encode(S.serialize()));
    println!("S2: {:?}", hex::encode(S2.serialize()));

    if S != S2 {
        panic!("shared secret does not match");
    }

    // 4.
    // In general, in both Bitcoin and Ethereum (including correctly-designed
    // ERC-4337 accounts), an address is a hash containing the public key used
    // to verify transactions from that address. So you can compute the address
    // if you compute the public key. To compute the public key, Alice or Bob
    // can compute P = M + G * hash(S)

    let temp = BigUint::from_bytes_be(S.serialize().as_slice());
    let order = BigUint::from_bytes_be(CURVE_ORDER.as_slice());
    let hashS = temp.mod_floor(&order); // hash(S)
    let mut hash_s = [0u8; 32];
    hash_s[..].copy_from_slice(hashS.to_bytes_be().as_slice());

    // println!("hashS: {}",  hex::encode(hashS.to_bytes_be()))

    let mut g_slice = [02u8; 33];
    g_slice[1..].copy_from_slice(&GENERATOR_X);
    let G = PublicKey::from_slice(&g_slice).unwrap();
    let scalar = secp256k1::Scalar::from_be_bytes(hash_s).unwrap();
    let GS = G.mul_tweak(&secp, &scalar).unwrap(); //  G * hash(S)
    let P = M.combine(&GS).unwrap(); // P = M + G * hash(S)

    println!("P: {:?}", hex::encode(P.serialize()));

    let temp = P.serialize_uncompressed();
    let temp = Keccak256::digest(&temp[1..]);
    let temp = &temp.as_slice()[12..];

    let stealth_address = H160::from_slice(temp);

    println!("A: {:?}", stealth_address);

    // 5.
    // To compute the private key for that address, Bob (and Bob alone) can compute
    // p = m + hash(S)

    let m_big = BigUint::from_bytes_be(m.secret_bytes().as_slice());
    let p = m_big.add(hashS); // p = m + hash(S)
    let p = p.mod_floor(&order); // p = p % N,  private key must be less than the order of the curve

    println!("p: {:?}", hex::encode(p.to_bytes_be()));

    // 6.
    // private key to public key

    let mut p_slice = [0u8; 32];
    p_slice[..].copy_from_slice(p.to_bytes_be().as_slice());
    let scalar = secp256k1::Scalar::from_be_bytes(p_slice).unwrap();
    let P2 = G.mul_tweak(&secp, &scalar).unwrap(); // P2 = G * p

    println!("P2: {:?}", hex::encode(P2.serialize()));

    if P != P2 {
        panic!("public key does not match");
    }
}
