// SPDX-License-Identifier: CC0-1.0

//! Tidecoin's ML-KEM-backed v2 packet cipher.

use alloc::vec::Vec;
use core::fmt;

use chacha20_poly1305::chacha20::{ChaCha20, Key, Nonce};
use chacha20_poly1305::ChaCha20Poly1305;
use hashes::{hkdf::Hkdf, sha256};
use zeroize::Zeroize;

use crate::Magic;

const AEAD_EXPANSION: usize = 16;

fn nonce96(prefix: u32, suffix: u64) -> Nonce {
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(&prefix.to_le_bytes());
    nonce[4..].copy_from_slice(&suffix.to_le_bytes());
    Nonce::new(nonce)
}

fn hkdf_expand_32(hkdf: &Hkdf<sha256::HashEngine>, info: &[u8]) -> [u8; 32] {
    let mut okm = [0_u8; 32];
    match hkdf.expand(info, &mut okm) {
        Ok(()) => okm,
        Err(_) => unreachable!("32-byte HKDF output is always valid"),
    }
}

#[derive(Clone)]
struct FsChaCha20 {
    chacha20: ChaCha20,
    rekey_interval: u32,
    chunk_counter: u32,
    rekey_counter: u64,
}

impl FsChaCha20 {
    fn new(key: [u8; 32], rekey_interval: u32) -> Self {
        Self {
            chacha20: ChaCha20::new(Key::new(key), nonce96(0, 0), 0),
            rekey_interval,
            chunk_counter: 0,
            rekey_counter: 0,
        }
    }

    fn crypt(&mut self, input: &[u8], output: &mut [u8]) {
        debug_assert_eq!(input.len(), output.len());
        output.copy_from_slice(input);
        self.chacha20.apply_keystream(output);

        self.chunk_counter += 1;
        if self.chunk_counter == self.rekey_interval {
            let mut new_key = [0_u8; 32];
            self.chacha20.apply_keystream(&mut new_key);
            self.rekey_counter += 1;
            self.chacha20 = ChaCha20::new(Key::new(new_key), nonce96(0, self.rekey_counter), 0);
            new_key.zeroize();
            self.chunk_counter = 0;
        }
    }
}

impl Drop for FsChaCha20 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for FsChaCha20 {
    fn zeroize(&mut self) {
        self.chacha20 = ChaCha20::new(Key::new([0_u8; 32]), nonce96(0, 0), 0);
        self.rekey_interval = 0;
        self.chunk_counter = 0;
        self.rekey_counter = 0;
    }
}

#[derive(Clone)]
struct FsChaCha20Poly1305 {
    key: [u8; 32],
    rekey_interval: u32,
    packet_counter: u32,
    rekey_counter: u64,
}

impl FsChaCha20Poly1305 {
    fn new(key: [u8; 32], rekey_interval: u32) -> Self {
        Self { key, rekey_interval, packet_counter: 0, rekey_counter: 0 }
    }

    fn cipher(&self, nonce: Nonce) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::new(self.key), nonce)
    }

    fn keystream(&self, nonce: Nonce, out: &mut [u8]) {
        out.fill(0);
        let _ = self.cipher(nonce).encrypt(out, None);
    }

    fn next_packet(&mut self) {
        self.packet_counter += 1;
        if self.packet_counter == self.rekey_interval {
            let mut one_block = [0_u8; 64];
            self.keystream(nonce96(u32::MAX, self.rekey_counter), &mut one_block);
            self.key.copy_from_slice(&one_block[..32]);
            one_block.zeroize();
            self.packet_counter = 0;
            self.rekey_counter += 1;
        }
    }

    fn encrypt(
        &mut self,
        plain1: &[u8],
        plain2: &[u8],
        aad: &[u8],
        cipher: &mut [u8],
    ) -> Result<(), Bip324PqError> {
        let plain_len = plain1.len() + plain2.len();
        let expected = plain_len + AEAD_EXPANSION;
        if cipher.len() != expected {
            return Err(Bip324PqError::InvalidLength { expected, got: cipher.len() });
        }

        let mut payload = Vec::with_capacity(plain_len);
        payload.extend_from_slice(plain1);
        payload.extend_from_slice(plain2);
        let tag = self
            .cipher(nonce96(self.packet_counter, self.rekey_counter))
            .encrypt(&mut payload, Some(aad));
        cipher[..plain_len].copy_from_slice(&payload);
        cipher[plain_len..].copy_from_slice(&tag);
        self.next_packet();
        Ok(())
    }

    fn decrypt(
        &mut self,
        cipher: &[u8],
        aad: &[u8],
        plain1: &mut [u8],
        plain2: &mut [u8],
    ) -> Result<(), Bip324PqError> {
        let plain_len = plain1.len() + plain2.len();
        let expected = plain_len + AEAD_EXPANSION;
        if cipher.len() != expected {
            return Err(Bip324PqError::InvalidLength { expected, got: cipher.len() });
        }

        let mut payload = cipher[..plain_len].to_vec();
        let tag: [u8; AEAD_EXPANSION] =
            cipher[plain_len..].try_into().expect("validated tag length");
        let result = self
            .cipher(nonce96(self.packet_counter, self.rekey_counter))
            .decrypt(&mut payload, tag, Some(aad))
            .map_err(|_| Bip324PqError::AuthenticationFailed);
        self.next_packet();
        result?;
        plain1.copy_from_slice(&payload[..plain1.len()]);
        plain2.copy_from_slice(&payload[plain1.len()..]);
        Ok(())
    }
}

impl Drop for FsChaCha20Poly1305 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for FsChaCha20Poly1305 {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.rekey_interval = 0;
        self.packet_counter = 0;
        self.rekey_counter = 0;
    }
}

/// Errors returned by the Tidecoin v2 PQ packet cipher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bip324PqError {
    /// The provided buffer length does not match the expected protocol length.
    InvalidLength {
        /// Expected number of bytes.
        expected: usize,
        /// Actual number of bytes provided.
        got: usize,
    },
    /// The message body exceeds the 24-bit packet length field.
    MessageTooLong(usize),
    /// Packet authentication failed.
    AuthenticationFailed,
}

impl fmt::Display for Bip324PqError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, got } => {
                write!(f, "invalid length: expected {} bytes, got {}", expected, got)
            }
            Self::MessageTooLong(len) => {
                write!(f, "message too long for 24-bit length field: {}", len)
            }
            Self::AuthenticationFailed => write!(f, "packet authentication failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Bip324PqError {}

/// The Tidecoin v2 PQ packet cipher.
#[derive(Clone)]
pub struct Bip324PqCipher {
    send_l_cipher: FsChaCha20,
    recv_l_cipher: FsChaCha20,
    send_p_cipher: FsChaCha20Poly1305,
    recv_p_cipher: FsChaCha20Poly1305,
    session_id: [u8; Self::SESSION_ID_LEN],
    send_garbage_terminator: [u8; Self::GARBAGE_TERMINATOR_LEN],
    recv_garbage_terminator: [u8; Self::GARBAGE_TERMINATOR_LEN],
}

impl Bip324PqCipher {
    /// Session identifier length.
    pub const SESSION_ID_LEN: usize = 32;
    /// Garbage terminator length.
    pub const GARBAGE_TERMINATOR_LEN: usize = 16;
    /// Rekey interval shared with Tidecoin node.
    pub const REKEY_INTERVAL: u32 = 224;
    /// Encrypted length prefix size.
    pub const LENGTH_LEN: usize = 3;
    /// Encrypted packet header size.
    pub const HEADER_LEN: usize = 1;
    /// Packet expansion excluding payload bytes.
    pub const EXPANSION: usize = Self::LENGTH_LEN + Self::HEADER_LEN + AEAD_EXPANSION;
    /// Ignore-bit flag in the encrypted packet header.
    pub const IGNORE_BIT: u8 = 0x80;

    /// Initializes the packet cipher from a 32-byte shared secret.
    pub fn from_shared_secret(shared_secret: &[u8; 32], magic: Magic, initiator: bool) -> Self {
        Self::from_shared_secret_with_self_decrypt(shared_secret, magic, initiator, false)
    }

    /// Initializes the packet cipher from an ML-KEM shared secret.
    /// Initializes the packet cipher and optionally swaps send/receive keys for self-decrypt tests.
    pub fn from_shared_secret_with_self_decrypt(
        shared_secret: &[u8; 32],
        magic: Magic,
        initiator: bool,
        self_decrypt: bool,
    ) -> Self {
        let mut salt = b"tidecoin_v2_kem".to_vec();
        salt.extend_from_slice(&magic.to_bytes());

        let hkdf = Hkdf::<sha256::HashEngine>::new(&salt, shared_secret);
        let side = initiator != self_decrypt;

        let mut initiator_l = hkdf_expand_32(&hkdf, b"initiator_L");
        let mut initiator_p = hkdf_expand_32(&hkdf, b"initiator_P");
        let mut responder_l = hkdf_expand_32(&hkdf, b"responder_L");
        let mut responder_p = hkdf_expand_32(&hkdf, b"responder_P");
        let mut garbage = hkdf_expand_32(&hkdf, b"garbage_terminators");
        let mut session_id = hkdf_expand_32(&hkdf, b"session_id");

        let mut send_l = if side { initiator_l } else { responder_l };
        let mut recv_l = if side { responder_l } else { initiator_l };
        let mut send_p = if side { initiator_p } else { responder_p };
        let mut recv_p = if side { responder_p } else { initiator_p };

        let mut send_garbage_terminator = [0_u8; Self::GARBAGE_TERMINATOR_LEN];
        let mut recv_garbage_terminator = [0_u8; Self::GARBAGE_TERMINATOR_LEN];
        if initiator {
            send_garbage_terminator.copy_from_slice(&garbage[..Self::GARBAGE_TERMINATOR_LEN]);
            recv_garbage_terminator.copy_from_slice(&garbage[Self::GARBAGE_TERMINATOR_LEN..]);
        } else {
            recv_garbage_terminator.copy_from_slice(&garbage[..Self::GARBAGE_TERMINATOR_LEN]);
            send_garbage_terminator.copy_from_slice(&garbage[Self::GARBAGE_TERMINATOR_LEN..]);
        }

        let cipher = Self {
            send_l_cipher: FsChaCha20::new(send_l, Self::REKEY_INTERVAL),
            recv_l_cipher: FsChaCha20::new(recv_l, Self::REKEY_INTERVAL),
            send_p_cipher: FsChaCha20Poly1305::new(send_p, Self::REKEY_INTERVAL),
            recv_p_cipher: FsChaCha20Poly1305::new(recv_p, Self::REKEY_INTERVAL),
            session_id,
            send_garbage_terminator,
            recv_garbage_terminator,
        };

        initiator_l.zeroize();
        initiator_p.zeroize();
        responder_l.zeroize();
        responder_p.zeroize();
        garbage.zeroize();
        session_id.zeroize();
        send_l.zeroize();
        recv_l.zeroize();
        send_p.zeroize();
        recv_p.zeroize();

        cipher
    }

    /// Encrypts one packet into `output`.
    ///
    /// # Errors
    ///
    /// Returns an error if `contents` exceeds the 24-bit packet length limit or if `output`
    /// does not have the exact protocol length `contents.len() + EXPANSION`.
    pub fn encrypt(
        &mut self,
        contents: &[u8],
        aad: &[u8],
        ignore: bool,
        output: &mut [u8],
    ) -> Result<(), Bip324PqError> {
        if contents.len() > 0xFF_FFFF {
            return Err(Bip324PqError::MessageTooLong(contents.len()));
        }
        let expected = contents.len() + Self::EXPANSION;
        if output.len() != expected {
            return Err(Bip324PqError::InvalidLength { expected, got: output.len() });
        }

        let len = [
            (contents.len() & 0xFF) as u8,
            ((contents.len() >> 8) & 0xFF) as u8,
            ((contents.len() >> 16) & 0xFF) as u8,
        ];
        self.send_l_cipher.crypt(&len, &mut output[..Self::LENGTH_LEN]);

        let header = [if ignore { Self::IGNORE_BIT } else { 0 }];
        self.send_p_cipher.encrypt(&header, contents, aad, &mut output[Self::LENGTH_LEN..])
    }

    /// Decrypts the packet length prefix.
    ///
    /// # Errors
    ///
    /// Returns an error if `input` is not exactly three bytes long.
    pub fn decrypt_length(&mut self, input: &[u8]) -> Result<u32, Bip324PqError> {
        if input.len() != Self::LENGTH_LEN {
            return Err(Bip324PqError::InvalidLength {
                expected: Self::LENGTH_LEN,
                got: input.len(),
            });
        }
        let mut buf = [0_u8; Self::LENGTH_LEN];
        self.recv_l_cipher.crypt(input, &mut buf);
        let len = u32::from(buf[0]) | (u32::from(buf[1]) << 8) | (u32::from(buf[2]) << 16);
        buf.zeroize();
        Ok(len)
    }

    /// Decrypts one packet body and returns whether the ignore bit was set.
    ///
    /// # Errors
    ///
    /// Returns an error if `input` does not have the exact protocol length for `contents` or if
    /// packet authentication fails.
    pub fn decrypt(
        &mut self,
        input: &[u8],
        aad: &[u8],
        contents: &mut [u8],
    ) -> Result<bool, Bip324PqError> {
        let expected = contents.len() + Self::HEADER_LEN + AEAD_EXPANSION;
        if input.len() != expected {
            return Err(Bip324PqError::InvalidLength { expected, got: input.len() });
        }

        let mut header = [0_u8; Self::HEADER_LEN];
        self.recv_p_cipher.decrypt(input, aad, &mut header, contents)?;
        let ignore = (header[0] & Self::IGNORE_BIT) == Self::IGNORE_BIT;
        header.zeroize();
        Ok(ignore)
    }

    /// Returns the transport session identifier.
    pub fn session_id(&self) -> &[u8; Self::SESSION_ID_LEN] {
        &self.session_id
    }

    /// Returns the garbage terminator this side should send.
    pub fn send_garbage_terminator(&self) -> &[u8; Self::GARBAGE_TERMINATOR_LEN] {
        &self.send_garbage_terminator
    }

    /// Returns the garbage terminator this side expects to receive.
    pub fn receive_garbage_terminator(&self) -> &[u8; Self::GARBAGE_TERMINATOR_LEN] {
        &self.recv_garbage_terminator
    }
}

impl Drop for Bip324PqCipher {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for Bip324PqCipher {
    fn zeroize(&mut self) {
        self.send_l_cipher.zeroize();
        self.recv_l_cipher.zeroize();
        self.send_p_cipher.zeroize();
        self.recv_p_cipher.zeroize();
        self.session_id.zeroize();
        self.send_garbage_terminator.zeroize();
        self.recv_garbage_terminator.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use core::mem::needs_drop;

    use super::*;

    fn hex_vec(s: &str) -> Vec<u8> {
        hex::decode_to_vec(s).expect("valid hex")
    }

    #[test]
    fn fs_chacha20_matches_node_vectors() {
        let cases = [
            (
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "0000000000000000000000000000000000000000000000000000000000000000",
                256_u32,
                "a93df4ef03011f3db95f60d996e1785df5de38fc39bfcb663a47bb5561928349",
            ),
            ("01", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", 5_u32, "ea"),
            (
                "e93fdb5c762804b9a706816aca31e35b11d2aa3080108ef46a5b1f1508819c0a",
                "8ec4c3ccdaea336bdeb245636970be01266509b33f3d2642504eaf412206207a",
                4096_u32,
                "8bfaa4eacff308fdb4a94a5ff25bd9d0c1f84b77f81239f67ff39d6e1ac280c9",
            ),
        ];

        for (plain_hex, key_hex, rekey_interval, expected_hex) in cases {
            let plaintext = hex_vec(plain_hex);
            let key: [u8; 32] = hex_vec(key_hex).try_into().expect("32-byte key");
            let expected = hex_vec(expected_hex);

            let mut fs = FsChaCha20::new(key, rekey_interval);
            let mut output = vec![0_u8; plaintext.len()];
            let mut chacha = ChaCha20::new(Key::new(key), nonce96(0, 0), 0);
            let mut baseline = vec![0_u8; plaintext.len()];

            for _ in 0..rekey_interval {
                fs.crypt(&plaintext, &mut output);
                baseline.copy_from_slice(&plaintext);
                chacha.apply_keystream(&mut baseline);
                assert_eq!(baseline, output);
            }

            fs.crypt(&plaintext, &mut output);
            let mut baseline_after = plaintext.clone();
            let mut chacha_copy = chacha;
            chacha.apply_keystream(&mut baseline_after);
            assert_ne!(baseline_after, output);

            let mut new_key = [0_u8; 32];
            chacha_copy.apply_keystream(&mut new_key);
            let mut rotated = ChaCha20::new(Key::new(new_key), nonce96(0, 1), 0);
            let mut rotated_output = plaintext.clone();
            rotated.apply_keystream(&mut rotated_output);
            assert_eq!(rotated_output, output);
            assert_eq!(output, expected);
        }
    }

    #[test]
    fn fs_chacha20_poly1305_matches_node_vectors() {
        let cases = [
            (
                "d6a4cb04ef0f7c09c1866ed29dc24d820e75b0491032a51b4c3366f9ca35c19ea3047ec6be9d45f9637b63e1cf9eb4c2523a5aab7b851ebeba87199db0e839cf0d5c25e50168306377aedbe9089fd2463ded88b83211cf51b73b150608cc7a600d0f11b9a742948482e1b109d8faf15b450aa7322e892fa2208c6691e3fecf4c711191b14d75a72147",
                "786cb9b6ebf44288974cf0",
                "5c9e1c3951a74fba66708bf9d2c217571684556b6a6a3573bff2847d38612654",
                500_u64,
                "9dcebbd3281ea3dd8e9a1ef7d55a97abd6743e56ebc0c190cb2c4e14160b385e0bf508dddf754bd02c7c208447c131ce23e47a4a14dfaf5dd8bc601323950f754e05d46e9232f83fc5120fbbef6f5347a826ec79a93820718d4ec7a2b7cfaaa44b21e16d726448b62f803811aff4f6d827ed78e738ce8a507b81a8ae131311928039213de18a5120dc9b7370baca878f50ff254418de3da50c",
            ),
            (
                "8349b7a2690b63d01204800c288ff1138a1d473c832c90ea8b3fc102d0bb3adc44261b247c7c3d6760bfbe979d061c305f46d94c0582ac3099f0bf249f8cb234",
                "",
                "3bd2093fcbcb0d034d8c569583c5425c1a53171ea299f8cc3bbf9ae3530adfce",
                60000_u64,
                "30a6757ff8439b975363f166a0fa0e36722ab35936abd704297948f45083f4d499433137ce931f7fca28a0acd3bc30f57b550acbc21cbd45bbef0739d9caf30c14b94829deb27f0b1923a2af704ae5d6",
            ),
        ];

        for (plain_hex, aad_hex, key_hex, msg_idx, expected_hex) in cases {
            let plain = hex_vec(plain_hex);
            let aad = hex_vec(aad_hex);
            let key: [u8; 32] = hex_vec(key_hex).try_into().expect("32-byte key");
            let expected = hex_vec(expected_hex);

            for prefix in [plain.len(), 0, plain.len() / 2] {
                let mut enc = FsChaCha20Poly1305::new(key, 224);
                let dummy_plain = [];
                let mut dummy_cipher = [0_u8; AEAD_EXPANSION];
                for _ in 0..msg_idx {
                    enc.encrypt(&dummy_plain, &dummy_plain, &dummy_plain, &mut dummy_cipher)
                        .expect("dummy encrypt");
                }

                let mut cipher = vec![0_u8; plain.len() + AEAD_EXPANSION];
                enc.encrypt(&plain[..prefix], &plain[prefix..], &aad, &mut cipher)
                    .expect("encrypt");
                assert_eq!(cipher, expected);

                let mut dec = FsChaCha20Poly1305::new(key, 224);
                for _ in 0..msg_idx {
                    let mut ignored = [];
                    let _ = dec.decrypt(&dummy_cipher, &dummy_plain, &mut ignored, &mut []);
                }

                let mut plain_out = vec![0_u8; plain.len()];
                let (prefix_out, suffix_out) = plain_out.split_at_mut(prefix);
                dec.decrypt(&cipher, &aad, prefix_out, suffix_out).expect("decrypt");
                assert_eq!(plain_out, plain);
            }
        }
    }

    #[test]
    fn cipher_roundtrip_matches_node_behavior() {
        let mut shared_secret = [0_u8; 32];
        for (i, byte) in shared_secret.iter_mut().enumerate() {
            *byte = i as u8;
        }

        let mut initiator =
            Bip324PqCipher::from_shared_secret(&shared_secret, Magic::TIDECOIN, true);
        let mut responder =
            Bip324PqCipher::from_shared_secret(&shared_secret, Magic::TIDECOIN, false);

        assert_eq!(initiator.session_id(), responder.session_id());
        assert_eq!(initiator.send_garbage_terminator(), responder.receive_garbage_terminator());
        assert_eq!(initiator.receive_garbage_terminator(), responder.send_garbage_terminator());

        let aad = hex_vec("a1b2c3");
        let msg = hex_vec("deadbeef");
        let mut ciphertext = vec![0_u8; msg.len() + Bip324PqCipher::EXPANSION];
        initiator.encrypt(&msg, &aad, false, &mut ciphertext).expect("encrypt");

        let len = responder
            .decrypt_length(&ciphertext[..Bip324PqCipher::LENGTH_LEN])
            .expect("decrypt len");
        assert_eq!(len as usize, msg.len());

        let mut decoded = vec![0_u8; len as usize];
        let ignore = responder
            .decrypt(&ciphertext[Bip324PqCipher::LENGTH_LEN..], &aad, &mut decoded)
            .expect("decrypt");
        assert!(!ignore);
        assert_eq!(decoded, msg);
    }

    #[test]
    fn cipher_detects_corruption() {
        let shared_secret = [7_u8; 32];
        let mut initiator =
            Bip324PqCipher::from_shared_secret(&shared_secret, Magic::TIDECOIN, true);
        let mut responder =
            Bip324PqCipher::from_shared_secret(&shared_secret, Magic::TIDECOIN, false);

        let aad = hex_vec("01020304");
        let msg = hex_vec("cafebabe");
        let mut ciphertext = vec![0_u8; msg.len() + Bip324PqCipher::EXPANSION];
        initiator.encrypt(&msg, &aad, true, &mut ciphertext).expect("encrypt");
        ciphertext[Bip324PqCipher::LENGTH_LEN + 2] ^= 0x01;

        let len = responder
            .decrypt_length(&ciphertext[..Bip324PqCipher::LENGTH_LEN])
            .expect("decrypt len");
        let mut decoded = vec![0_u8; len as usize];
        let err = responder
            .decrypt(&ciphertext[Bip324PqCipher::LENGTH_LEN..], &aad, &mut decoded)
            .expect_err("corruption must fail");
        assert_eq!(err, Bip324PqError::AuthenticationFailed);
    }

    #[test]
    fn cipher_types_require_drop_for_zeroization() {
        assert!(needs_drop::<FsChaCha20>());
        assert!(needs_drop::<FsChaCha20Poly1305>());
        assert!(needs_drop::<Bip324PqCipher>());
    }
}
