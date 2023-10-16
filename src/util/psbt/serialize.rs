// Rust Bitcoin Library
// Written by
//   The Rust Bitcoin developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! PSBT serialization.
//!
//! Defines traits used for (de)serializing PSBT values into/from raw
//! bytes from/as PSBT key-value pairs.
//!

use prelude::*;

use io;

use blockdata::script::Script;
use blockdata::witness::Witness;
use blockdata::transaction::{Transaction, TxOut};
use consensus::encode::{self, serialize, Decodable, Encodable};
use secp256k1;
use util::bip32::{ChildNumber, Fingerprint, KeySource};
use hashes::{hash160, ripemd160, sha256, sha256d, Hash};
use util::ecdsa::{EcdsaSig, EcdsaSigError};
use util::psbt;
use schnorr;
use util::key::PublicKey;

use super::map::{PsbtSighashType};

/// A trait for serializing a value as raw data for insertion into PSBT
/// key-value pairs.
pub trait Serialize {
    /// Serialize a value as raw data.
    fn serialize(&self) -> Vec<u8>;
}

/// A trait for deserializing a value from raw data in PSBT key-value pairs.
pub trait Deserialize: Sized {
    /// Deserialize a value from raw data.
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error>;
}

impl_psbt_de_serialize!(Transaction);
impl_psbt_de_serialize!(TxOut);
impl_psbt_de_serialize!(Witness);
impl_psbt_hash_de_serialize!(ripemd160::Hash);
impl_psbt_hash_de_serialize!(sha256::Hash);
impl_psbt_hash_de_serialize!(hash160::Hash);
impl_psbt_hash_de_serialize!(sha256d::Hash);

impl Serialize for Script {
    fn serialize(&self) -> Vec<u8> {
        self.to_bytes()
    }
}

impl Deserialize for Script {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        Ok(Self::from(bytes.to_vec()))
    }
}

impl Serialize for PublicKey {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_into(&mut buf).expect("vecs don't error");
        buf
    }
}

impl Deserialize for PublicKey {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        PublicKey::from_slice(bytes)
            .map_err(|_| encode::Error::ParseFailed("invalid public key"))
    }
}

impl Serialize for secp256k1::PublicKey {
    fn serialize(&self) -> Vec<u8> {
        self.serialize().to_vec()
    }
}

impl Deserialize for secp256k1::PublicKey {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        secp256k1::PublicKey::from_slice(bytes)
            .map_err(|_| encode::Error::ParseFailed("invalid public key"))
    }
}

impl Serialize for EcdsaSig {
    fn serialize(&self) -> Vec<u8> {
        self.to_vec()
    }
}

impl Deserialize for EcdsaSig {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        // NB: Since BIP-174 says "the signature as would be pushed to the stack from
        // a scriptSig or witness" we should ideally use a consensus deserialization and do
        // not error on a non-standard values. However,
        //
        // 1) the current implementation of from_u32_consensus(`flag`) does not preserve
        // the sighash byte `flag` mapping all unknown values to EcdsaSighashType::All or
        // EcdsaSighashType::AllPlusAnyOneCanPay. Therefore, break the invariant
        // EcdsaSig::from_slice(&sl[..]).to_vec = sl.
        //
        // 2) This would cause to have invalid signatures because the sighash message
        // also has a field sighash_u32 (See BIP141). For example, when signing with non-standard
        // 0x05, the sighash message would have the last field as 0x05u32 while, the verification
        // would use check the signature assuming sighash_u32 as `0x01`.
        EcdsaSig::from_slice(&bytes)
            .map_err(|e| match e {
                EcdsaSigError::EmptySignature => {
                    encode::Error::ParseFailed("Empty partial signature data")
                }
                EcdsaSigError::NonStandardSighashType(flag) => {
                    encode::Error::from(psbt::Error::NonStandardSighashType(flag))
                }
                EcdsaSigError::Secp256k1(..) => {
                    encode::Error::ParseFailed("Invalid Ecdsa signature")
                }
                EcdsaSigError::HexEncoding(..) =>  {
                    unreachable!("Decoding from slice, not hex")
                }
            })
    }
}

impl Serialize for KeySource {
    fn serialize(&self) -> Vec<u8> {
        let mut rv: Vec<u8> = Vec::with_capacity(key_source_len(&self));

        rv.append(&mut self.0.to_bytes().to_vec());

        for cnum in self.1.into_iter() {
            rv.append(&mut serialize(&u32::from(*cnum)))
        }

        rv
    }
}

impl Deserialize for KeySource {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        if bytes.len() < 4 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into())
        }

        let fprint: Fingerprint = Fingerprint::from(&bytes[0..4]);
        let mut dpath: Vec<ChildNumber> = Default::default();

        let mut d = &bytes[4..];
        while !d.is_empty() {
            match u32::consensus_decode(&mut d) {
                Ok(index) => dpath.push(index.into()),
                Err(e) => return Err(e),
            }
        }

        Ok((fprint, dpath.into()))
    }
}

// partial sigs
impl Serialize for Vec<u8> {
    fn serialize(&self) -> Vec<u8> {
        self.clone()
    }
}

impl Deserialize for Vec<u8> {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        Ok(bytes.to_vec())
    }
}

impl Serialize for PsbtSighashType {
    fn serialize(&self) -> Vec<u8> {
        serialize(&self.to_u32())
    }
}

impl Deserialize for PsbtSighashType {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        let raw: u32 = encode::deserialize(bytes)?;
        Ok(PsbtSighashType { inner: raw })
    }
}


impl Serialize for schnorr::SchnorrSig  {
    fn serialize(&self) -> Vec<u8> {
        self.to_vec()
    }
}

impl Deserialize for schnorr::SchnorrSig {
    fn deserialize(bytes: &[u8]) -> Result<Self, encode::Error> {
        schnorr::SchnorrSig::from_slice(&bytes)
            .map_err(|e| match e {
                schnorr::SchnorrSigError::InvalidSighashType(flag) => {
                    encode::Error::from(psbt::Error::NonStandardSighashType(flag as u32))
                }
                schnorr::SchnorrSigError::InvalidSchnorrSigSize(_) => {
                    encode::Error::ParseFailed("Invalid Schnorr signature length")
                }
                schnorr::SchnorrSigError::Secp256k1(..) => {
                    encode::Error::ParseFailed("Invalid Schnorr signature")
                }
            })
    }
}
// Helper function to compute key source len
fn key_source_len(key_source: &KeySource) -> usize {
    4 + 4 * (key_source.1).as_ref().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_deserialize_non_standard_psbt_sighash_type() {
        let non_standard_sighash = [222u8, 0u8, 0u8, 0u8]; // 32 byte value.
        let sighash = PsbtSighashType::deserialize(&non_standard_sighash);
        assert!(sighash.is_ok())
    }
}
