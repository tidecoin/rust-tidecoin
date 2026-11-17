// SPDX-License-Identifier: CC0-1.0

//! Custom implementations must retain valid Rust values when erasure is requested.

use std::num::NonZeroU64;

use tidecoin_hashes::{sha256, Hash, HashEngine, Hkdf, HmacEngine};
use zeroize::Zeroize;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct CustomHash {
    bytes: [u8; 32],
    marker: NonZeroU64,
}

impl AsRef<[u8]> for CustomHash {
    fn as_ref(&self) -> &[u8] {
        self.as_byte_array()
    }
}

impl Hash for CustomHash {
    type Bytes = [u8; 32];

    fn from_byte_array(bytes: Self::Bytes) -> Self {
        Self { bytes, marker: NonZeroU64::new(7).unwrap() }
    }

    fn to_byte_array(self) -> Self::Bytes {
        assert_eq!(self.marker.get(), 7);
        self.bytes
    }

    fn as_byte_array(&self) -> &Self::Bytes {
        assert_eq!(self.marker.get(), 7);
        &self.bytes
    }
}

#[derive(Clone)]
struct CustomEngine {
    inner: sha256::HashEngine,
    marker: NonZeroU64,
    owned: Box<[u8; 8]>,
}

impl Default for CustomEngine {
    fn default() -> Self {
        Self {
            inner: sha256::HashEngine::default(),
            marker: NonZeroU64::new(7).unwrap(),
            owned: Box::new([42; 8]),
        }
    }
}

impl HashEngine for CustomEngine {
    type Hash = CustomHash;
    type Bytes = [u8; 32];
    const BLOCK_SIZE: usize = 64;

    fn input(&mut self, bytes: &[u8]) {
        self.inner.input(bytes);
    }
    fn n_bytes_hashed(&self) -> u64 {
        self.inner.n_bytes_hashed()
    }
    fn finalize(self) -> Self::Hash {
        CustomHash::from_byte_array(self.inner.clone().finalize().to_byte_array())
    }
}

impl Zeroize for CustomEngine {
    fn zeroize(&mut self) {
        // Preserve the nonzero marker and allocation while clearing their data.
        self.inner.zeroize();
        self.owned.as_mut().zeroize();
    }
}

impl Drop for CustomEngine {
    fn drop(&mut self) {
        assert_eq!(self.marker.get(), 7);
        assert!(self.owned.iter().all(|&b| b == 42) || self.owned.iter().all(|&b| b == 0));
    }
}

#[test]
fn hmac_erasure_preserves_custom_engine_invariants() {
    let mut first = HmacEngine::<CustomEngine>::new(b"first key");
    let mut second = HmacEngine::<CustomEngine>::new(b"second key");
    first.input(b"first message");
    second.input(b"second message");
    first.non_secure_erase();
    second.non_secure_erase();
    first.non_secure_erase();
    assert_eq!(first.n_bytes_hashed(), 0);
    assert_eq!(first.finalize().to_byte_array(), second.finalize().to_byte_array());
}

#[test]
fn hkdf_erasure_clears_bytes_without_zeroing_custom_hash_objects() {
    let mut hkdf = Hkdf::<CustomEngine>::new(b"salt", b"input key material");
    hkdf.non_secure_erase();
    hkdf.non_secure_erase();
    let mut actual = [0u8; 32];
    hkdf.expand(b"info", &mut actual).unwrap();

    // After explicit erasure, expansion uses an all-zero PRK, not the old key.
    let mut expected = HmacEngine::<CustomEngine>::new(&[0; 32]);
    expected.input(b"info");
    expected.input(&[1]);
    assert_eq!(actual, expected.finalize().to_byte_array());
    // Drop exercises the same erasure path, including when it was not explicit.
    drop(hkdf);
    drop(Hkdf::<CustomEngine>::new(b"salt", b"another input"));
}

fn check_builtin<E: HashEngine + Zeroize>(mut first: E, mut second: E) {
    first.input(b"first state");
    second.input(b"different state and length");
    first.zeroize();
    second.zeroize();
    first.zeroize();
    assert_eq!(first.n_bytes_hashed(), 0);
    assert_eq!(first.finalize().as_ref(), second.finalize().as_ref());
}

#[test]
fn builtin_engines_clear_previous_state() {
    use tidecoin_hashes::{
        hash160, ripemd160, sha1, sha256d, sha256t, sha384, sha3_256, sha512, sha512_256, siphash24,
    };
    check_builtin(sha1::HashEngine::default(), sha1::HashEngine::default());
    check_builtin(ripemd160::HashEngine::default(), ripemd160::HashEngine::default());
    check_builtin(sha256::HashEngine::default(), sha256::HashEngine::default());
    check_builtin(sha256d::HashEngine::default(), sha256d::HashEngine::default());
    check_builtin(hash160::HashEngine::default(), hash160::HashEngine::default());
    check_builtin(sha384::HashEngine::default(), sha384::HashEngine::default());
    check_builtin(sha512::HashEngine::default(), sha512::HashEngine::default());
    check_builtin(sha512_256::HashEngine::default(), sha512_256::HashEngine::default());
    check_builtin(sha3_256::HashEngine::default(), sha3_256::HashEngine::default());
    check_builtin(siphash24::HashEngine::with_keys(1, 2), siphash24::HashEngine::with_keys(3, 4));
    tidecoin_hashes::sha256t_tag! { struct TestTag = hash_str("erasure test"); }
    check_builtin(
        sha256t::HashEngine::<TestTag>::default(),
        sha256t::HashEngine::<TestTag>::default(),
    );
}
