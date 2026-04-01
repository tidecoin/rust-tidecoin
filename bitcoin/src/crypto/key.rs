// SPDX-License-Identifier: CC0-1.0

//! Tidecoin keys.
//!
//! This module provides keys used in Tidecoin that can be roundtrip
//! (de)serialized.

use core::convert::Infallible;
use core::fmt;
use core::str::FromStr;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use hashes::hash160;
use internals::array::ArrayExt;
use internals::array_vec::ArrayVec;
use internals::{impl_to_hex_from_lower_hex, write_err};
use io::{Read, Write};

use crate::crypto::ecdsa;
use crate::crypto::pq::{PqError, PqPublicKey, PqScheme, PqSecretKey};
use crate::hex::{self, DecodeFixedLengthBytesError};
use crate::internal_macros::impl_asref_push_bytes;
use crate::network::{Network, NetworkKind};
use crate::prelude::{DisplayHex, String, Vec};
use crate::script::{self, WitnessScriptBuf};
#[cfg(feature = "serde")]
use crate::serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "secp-recovery")]
use crate::sign_message::MessageSignature;

#[rustfmt::skip]                // Keep public re-exports separate.
pub use secp256k1::{constants, Parity, Verification};
pub use encapsulate::{
    CompressedPublicKey, Keypair, PrivateKey, PublicKey, SerializedXOnlyPublicKey, XOnlyPublicKey,
};
#[cfg(all(feature = "rand", feature = "std"))]
pub use secp256k1::rand;

/// Encapsulation module to provide a clear barrier for construction/destruction of types.
mod encapsulate {
    use secp256k1::Parity;

    /// A Bitcoin Schnorr X-only public key used for BIP-0340 signatures.
    ///
    /// This type also holds the parity of the full public key.
    #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct XOnlyPublicKey {
        inner: secp256k1::XOnlyPublicKey,
        parity: Parity,
    }

    impl XOnlyPublicKey {
        /// Constructs a new x-only public key from the provided secp256k1 x-only public key.
        pub fn from_secp(key: impl Into<secp256k1::XOnlyPublicKey>, parity: Parity) -> Self {
            Self { inner: key.into(), parity }
        }

        /// Sets the parity of this [`XOnlyPublicKey`].
        ///
        /// This returns a new `XOnlyPublicKey` with the same inner value, but the given parity.
        pub fn with_parity(self, parity: Parity) -> Self {
            Self { parity, ..self }
        }

        /// Returns the parity of this x-only public key.
        pub fn parity(&self) -> Parity {
            self.parity
        }

        /// Returns a reference to the inner secp256k1 x-only public key.
        #[inline]
        pub fn as_inner(&self) -> &secp256k1::XOnlyPublicKey {
            &self.inner
        }

        /// Returns the inner secp256k1 x-only public key.
        #[inline]
        pub fn to_inner(self) -> secp256k1::XOnlyPublicKey {
            self.inner
        }

        /// Returns the inner secp256k1 x-only public key.
        #[inline]
        #[deprecated(since = "TBD", note = "use `to_inner()` instead")]
        pub fn into_inner(self) -> secp256k1::XOnlyPublicKey {
            self.to_inner()
        }
    }

    /// A Bitcoin secret and public key pair.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    pub struct Keypair(secp256k1::Keypair);

    impl Keypair {
        /// Constructs a keypair from a provided secp256k1 keypair.
        #[inline]
        pub fn from_secp(keypair: impl Into<secp256k1::Keypair>) -> Self {
            Self(keypair.into())
        }

        /// Returns a reference to the inner [`secp256k1::Keypair`].
        #[inline]
        pub fn as_inner(&self) -> &secp256k1::Keypair {
            &self.0
        }
    }

    /// A Bitcoin ECDSA public key.
    #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct PublicKey {
        /// Whether this public key should be serialized as compressed.
        compressed: bool,
        /// The actual ECDSA key.
        inner: secp256k1::PublicKey,
    }

    impl PublicKey {
        /// Constructs a new compressed ECDSA public key from the provided secp256k1 public key.
        pub fn from_secp(key: impl Into<secp256k1::PublicKey>) -> Self {
            Self { compressed: true, inner: key.into() }
        }

        /// Constructs a new uncompressed (legacy) ECDSA public key from the provided secp256k1 public
        /// key.
        pub fn from_secp_uncompressed(key: impl Into<secp256k1::PublicKey>) -> Self {
            Self { compressed: false, inner: key.into() }
        }

        /// Returns the inner secp256k1 public key.
        #[inline]
        pub fn to_inner(self) -> secp256k1::PublicKey {
            self.inner
        }

        /// Returns whether this public key should be serialized as compressed.
        #[inline]
        pub fn compressed(&self) -> bool {
            self.compressed
        }
    }

    impl Drop for Keypair {
        fn drop(&mut self) {
            self.0.non_secure_erase();
        }
    }

    /// An always-compressed Bitcoin ECDSA public key.
    #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct CompressedPublicKey(secp256k1::PublicKey);

    impl CompressedPublicKey {
        /// Constructs a new compressed public key from the provided secp public key.
        #[inline]
        pub fn from_secp(inner: secp256k1::PublicKey) -> Self {
            Self(inner)
        }

        /// Returns the inner [`secp256k1::PublicKey`].
        #[inline]
        pub fn to_inner(self) -> secp256k1::PublicKey {
            self.0
        }
    }

    /// A Bitcoin ECDSA private key.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PrivateKey {
        /// Whether this private key should be serialized as compressed.
        compressed: bool,
        /// The actual ECDSA key.
        inner: secp256k1::SecretKey,
    }

    impl PrivateKey {
        /// Constructs a new compressed ECDSA private key from the provided secp256k1 private key.
        pub fn from_secp(key: secp256k1::SecretKey) -> Self {
            Self { compressed: true, inner: key }
        }

        /// Constructs a new uncompressed (legacy) ECDSA private key from the provided secp256k1
        /// private key.
        pub fn from_secp_uncompressed(key: secp256k1::SecretKey) -> Self {
            Self { compressed: false, inner: key }
        }

        /// Returns a reference to the inner secp256k1 secret key.
        #[inline]
        pub fn as_inner(&self) -> &secp256k1::SecretKey {
            &self.inner
        }

        /// Returns whether this private key should be serialized as compressed.
        #[inline]
        pub fn compressed(&self) -> bool {
            self.compressed
        }
    }

    impl Drop for PrivateKey {
        fn drop(&mut self) {
            self.inner.non_secure_erase();
        }
    }

    internals::transparent_newtype! {
        /// An array of bytes that's semantically an x-only public but was **not** validated.
        ///
        /// This can be useful when validation is not desired but semantics of the bytes should be
        /// preserved. The validation can still happen using `to_validated()` method.
        #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct SerializedXOnlyPublicKey([u8; 32]);

        impl SerializedXOnlyPublicKey {
            pub(crate) fn from_bytes_ref(bytes: &_) -> Self;
        }
    }

    impl SerializedXOnlyPublicKey {
        /// Marks the supplied bytes as a serialized x-only public key.
        pub const fn from_byte_array(bytes: [u8; 32]) -> Self {
            Self(bytes)
        }

        /// Returns the raw bytes.
        pub const fn to_byte_array(self) -> [u8; 32] {
            self.0
        }

        /// Returns a reference to the raw bytes.
        pub const fn as_byte_array(&self) -> &[u8; 32] {
            &self.0
        }
    }
}

impl XOnlyPublicKey {
    /// Constructs an x-only public key from a keypair.
    ///
    /// Returns the x-only public key, with the relevant parity set from the full public key.
    #[inline]
    pub fn from_keypair(keypair: &Keypair) -> Self {
        let (xonly, parity) = secp256k1::XOnlyPublicKey::from_keypair(keypair.as_inner());
        Self::from_secp(xonly, parity)
    }

    /// Constructs an x-only public key from a 32-byte x-coordinate.
    ///
    /// # Errors
    ///
    /// Errors if the provided bytes don't represent a valid secp256k1 point x-coordinate.
    #[inline]
    pub fn from_byte_array(
        data: &[u8; constants::SCHNORR_PUBLIC_KEY_SIZE],
    ) -> Result<Self, ParseXOnlyPublicKeyError> {
        secp256k1::XOnlyPublicKey::from_byte_array(*data)
            .map(|key| Self::from_secp(key, Parity::Even))
            .map_err(|_| ParseXOnlyPublicKeyError::InvalidXCoordinate)
    }

    /// Serializes the x-only public key as a byte-encoded x coordinate value (32 bytes).
    #[inline]
    pub fn serialize(&self) -> ([u8; constants::SCHNORR_PUBLIC_KEY_SIZE], Parity) {
        (self.as_inner().serialize(), self.parity())
    }

    /// Converts this x-only public key to a full public key.
    ///
    /// The [`PublicKey`] is constructed using the parity in this x-only public key.
    #[inline]
    pub fn to_public_key(self) -> PublicKey {
        self.as_inner().public_key(self.parity()).into()
    }

    /// Verifies that a tweak produced by [`XOnlyPublicKey::add_tweak`] was computed correctly.
    ///
    /// Should be called on the original untweaked key. Takes the tweaked key with its output parity from
    /// [`XOnlyPublicKey::add_tweak`] as input.
    #[inline]
    pub fn tweak_add_check(&self, tweaked_key: &Self, tweak: secp256k1::Scalar) -> bool {
        self.as_inner().tweak_add_check(tweaked_key.as_inner(), tweaked_key.parity(), tweak)
    }

    /// Tweaks an [`XOnlyPublicKey`] by adding the generator multiplied with the given tweak to it.
    ///
    /// # Returns
    ///
    /// The newly tweaked key. This key has its parity set according to the parity following the
    /// tweak. This key should be provided to `tweak_add_check` which can be used to verify a tweak
    /// more efficiently than regenerating it and checking equality.
    ///
    /// # Errors
    ///
    /// If the resulting key would be invalid.
    #[inline]
    pub fn add_tweak(&self, tweak: &secp256k1::Scalar) -> Result<Self, TweakXOnlyPublicKeyError> {
        match self.as_inner().add_tweak(tweak) {
            Ok((xonly, parity)) => Ok(Self::from_secp(xonly, parity)),
            Err(secp256k1::Error::InvalidTweak) => Err(TweakXOnlyPublicKeyError::BadTweak),
            Err(secp256k1::Error::InvalidParityValue(_)) => {
                Err(TweakXOnlyPublicKeyError::ParityError)
            }
            Err(_) => Err(TweakXOnlyPublicKeyError::ResultKeyInvalid),
        }
    }
}

impl FromStr for XOnlyPublicKey {
    type Err = ParseXOnlyPublicKeyError;
    fn from_str(s: &str) -> Result<Self, ParseXOnlyPublicKeyError> {
        secp256k1::XOnlyPublicKey::from_str(s)
            .map(Self::from)
            .map_err(|_| ParseXOnlyPublicKeyError::InvalidXCoordinate)
    }
}

impl From<secp256k1::XOnlyPublicKey> for XOnlyPublicKey {
    fn from(pk: secp256k1::XOnlyPublicKey) -> Self {
        Self::from_secp(pk, Parity::Even)
    }
}

impl From<secp256k1::PublicKey> for XOnlyPublicKey {
    fn from(pk: secp256k1::PublicKey) -> Self {
        let (xonly, parity) = pk.x_only_public_key();
        Self::from_secp(xonly, parity)
    }
}

impl fmt::LowerHex for XOnlyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self.as_inner(), f)
    }
}
// Allocate for serialized size
impl_to_hex_from_lower_hex!(XOnlyPublicKey, |_| constants::SCHNORR_PUBLIC_KEY_SIZE * 2);

impl fmt::Display for XOnlyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self.as_inner(), f)
    }
}

// XOnlyPublicKey should serialize/deserialize identically to the inner type.
#[cfg(feature = "serde")]
impl Serialize for XOnlyPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        <secp256k1::XOnlyPublicKey as Serialize>::serialize(self.as_inner(), serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for XOnlyPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self::from_secp(secp256k1::XOnlyPublicKey::deserialize(deserializer)?, Parity::Even))
    }
}

impl Keypair {
    /// Generates a new random key pair.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(all(feature = "rand", feature = "std"))] {
    /// use tidecoin::Keypair;
    ///
    /// let keypair = Keypair::generate();
    /// # }
    /// ```
    #[inline]
    #[cfg(all(feature = "rand", feature = "std"))]
    pub fn generate() -> Self {
        let kp = secp256k1::Keypair::new(&mut rand::rng());
        Self::from_secp(kp)
    }

    /// Constructs a [`Keypair`] directly from a secp256k1 secret key.
    #[inline]
    pub fn from_secret_key(sk: &secp256k1::SecretKey) -> Self {
        Self::from(secp256k1::Keypair::from_secret_key(sk))
    }

    /// Returns the [`secp256k1::SecretKey`] for this [`Keypair`].
    ///
    /// This is equivalent to using [`secp256k1::SecretKey::from_keypair`] on the inner value.
    #[inline]
    pub fn to_secret_key(&self) -> secp256k1::SecretKey {
        secp256k1::SecretKey::from_keypair(self.as_inner())
    }

    /// Returns the secret bytes for this [`Keypair`].
    #[inline]
    pub fn to_secret_bytes(&self) -> [u8; constants::SECRET_KEY_SIZE] {
        self.as_inner().to_secret_bytes()
    }

    /// Returns the [`PublicKey`] for this [`Keypair`].
    ///
    /// This is equivalent to using [`PublicKey::from_keypair`].
    #[inline]
    pub fn to_public_key(&self) -> PublicKey {
        PublicKey::from_keypair(self)
    }

    /// Returns the [`XOnlyPublicKey`] for this [`Keypair`].
    ///
    /// This is equivalent to using [`XOnlyPublicKey::from_keypair`].
    #[inline]
    pub fn to_x_only_public_key(&self) -> XOnlyPublicKey {
        XOnlyPublicKey::from_keypair(self)
    }

    /// Schnorr sign a message slice with this keypair.
    ///
    /// If the `rand` and `std` features are enabled, this function will randomly seed auxiliary
    /// data. Otherwise, this will use no auxiliary data.
    #[inline]
    pub fn raw_bip340_sign(&self, msg: &[u8]) -> secp256k1::schnorr::Signature {
        #[cfg(not(all(feature = "rand", feature = "std")))]
        {
            secp256k1::schnorr::sign_no_aux_rand(msg, self.as_inner())
        }
        #[cfg(all(feature = "rand", feature = "std"))]
        {
            secp256k1::schnorr::sign(msg, self.as_inner())
        }
    }

    /// Schnorr sign a message slice with this keypair, using provided auxiliary random data.
    #[inline]
    pub fn raw_bip340_sign_with_aux_randomness(
        &self,
        msg: &[u8],
        aux_rand: &[u8; 32],
    ) -> secp256k1::schnorr::Signature {
        secp256k1::schnorr::sign_with_aux_rand(msg, self.as_inner(), aux_rand)
    }
}

impl FromStr for Keypair {
    type Err = ParseKeypairError;
    fn from_str(s: &str) -> Result<Self, ParseKeypairError> {
        secp256k1::Keypair::from_str(s).map(Self::from).map_err(ParseKeypairError)
    }
}

impl From<secp256k1::Keypair> for Keypair {
    fn from(pk: secp256k1::Keypair) -> Self {
        Self::from_secp(pk)
    }
}

impl From<Keypair> for secp256k1::PublicKey {
    fn from(kp: Keypair) -> Self {
        kp.to_public_key().to_inner()
    }
}

impl PublicKey {
    /// Constructs a new compressed ECDSA public key from the provided generic secp256k1 public key.
    #[deprecated(since = "TBD", note = "use `from_secp` instead")]
    pub fn new(key: impl Into<secp256k1::PublicKey>) -> Self {
        Self::from_secp(key)
    }

    /// Constructs a new uncompressed (legacy) ECDSA public key from the provided generic secp256k1
    /// public key.
    #[deprecated(since = "TBD", note = "use `from_secp_uncompressed` instead")]
    pub fn new_uncompressed(key: impl Into<secp256k1::PublicKey>) -> Self {
        Self::from_secp_uncompressed(key)
    }

    /// Serializes the key as a byte-encoded pair of values.
    ///
    /// This will call the provided function with the key as a byte slice in either
    /// compressed or uncompressed form.
    ///
    /// See [`PublicKey::serialize_compressed`] and [`PublicKey::serialize_uncompressed`]
    /// for more information on the byte formats for the key.
    ///
    /// # Examples
    ///
    /// ```
    /// use tidecoin::PublicKey;
    /// use tidecoin::hashes::hash160;
    ///
    /// let key = "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8"
    ///     .parse::<PublicKey>()
    ///     .unwrap();
    /// assert!(key.compressed());
    /// let vec_out = key.with_serialized(<[_]>::to_vec);
    /// assert_eq!(vec_out.len(), 33);
    ///
    /// let hash = key.with_serialized(hash160::Hash::hash).to_string();
    /// assert_eq!(hash, "dabedb4de2bd2bfec5d38475b9c64af13999a043");
    /// ```
    pub fn with_serialized<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        if self.compressed() {
            f(&self.serialize_compressed())
        } else {
            f(&self.serialize_uncompressed())
        }
    }

    /// Serializes the key as a byte-encoded pair of values.
    ///
    /// This function serializes the key in compressed form, where the y-coordinate is
    /// represented by only a single bit, as x determines it up to one bit.
    ///
    /// If you want to serialize while considering the compressedness of this key,
    /// use [`with_serialized`] instead.
    ///
    /// [`with_serialized`]: PublicKey::with_serialized
    pub fn serialize_compressed(&self) -> [u8; 33] {
        self.to_inner().serialize()
    }

    /// Serializes the key as a byte-encoded pair of values, in uncompressed form.
    ///
    /// If you want to serialize while considering the compressedness of this key,
    /// use [`with_serialized`] instead.
    ///
    /// [`with_serialized`]: PublicKey::with_serialized
    pub fn serialize_uncompressed(&self) -> [u8; 65] {
        self.to_inner().serialize_uncompressed()
    }

    /// Returns bitcoin 160-bit hash of the public key.
    pub fn pubkey_hash(&self) -> PubkeyHash {
        PubkeyHash(self.with_serialized(hash160::Hash::hash))
    }

    /// Returns bitcoin 160-bit hash of the public key for witness program
    ///
    /// # Errors
    ///
    /// Errors if this key is not compressed.
    pub fn wpubkey_hash(&self) -> Result<WPubkeyHash, UncompressedPublicKeyError> {
        if self.compressed() {
            Ok(WPubkeyHash::from_byte_array(
                hash160::Hash::hash(&self.to_inner().serialize()).to_byte_array(),
            ))
        } else {
            Err(UncompressedPublicKeyError)
        }
    }

    /// Returns the script code used to spend a P2WPKH input.
    ///
    /// While the type returned is [`WitnessScriptBuf`], this is **not** a witness script and
    /// should not be used as one. It is a special template defined in BIP 143 which is used
    /// in place of a witness script for purposes of sighash computation.
    ///
    /// # Errors
    ///
    /// Errors if this key is not compressed.
    pub fn p2wpkh_script_code(&self) -> Result<WitnessScriptBuf, UncompressedPublicKeyError> {
        let key = CompressedPublicKey::try_from(*self)?;
        Ok(key.p2wpkh_script_code())
    }

    /// Converts this [`PublicKey`] into a [`CompressedPublicKey`] infallibly.
    ///
    /// Unlike the `TryFrom` implementation, this function will discard compressedness
    /// information on the [`PublicKey`].
    pub fn force_compressed(self) -> CompressedPublicKey {
        CompressedPublicKey::from_secp(self.to_inner())
    }

    /// Writes the public key into a writer.
    ///
    /// # Errors
    ///
    /// Errors if the bytes fail to write to the provided writer.
    pub fn write_into<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
        self.with_serialized(|bytes| writer.write_all(bytes))
    }

    /// Reads the public key from a reader.
    ///
    /// This internally reads the first byte before reading the rest, so
    /// use of a `BufReader` is recommended.
    ///
    /// # Errors
    ///
    /// Errors if the reader fails to read, or the read bytes are not a valid public key.
    pub fn read_from<R: Read + ?Sized>(reader: &mut R) -> Result<Self, io::Error> {
        let mut bytes = [0; 65];

        reader.read_exact(&mut bytes[0..1])?;
        let bytes = if bytes[0] < 4 { &mut bytes[..33] } else { &mut bytes[..65] };

        reader.read_exact(&mut bytes[1..])?;
        Self::from_slice(bytes).map_err(|e| {
            // Need a static string for no-std io
            #[cfg(feature = "std")]
            let reason = e;
            #[cfg(not(feature = "std"))]
            let reason = match e {
                FromSliceError::Secp256k1(_) => "secp256k1 error",
                FromSliceError::InvalidKeyPrefix(_) => "invalid key prefix",
                FromSliceError::InvalidLength(_) => "invalid length",
            };
            io::Error::new(io::ErrorKind::InvalidData, reason)
        })
    }

    /// Serializes the public key to bytes.
    #[deprecated(since = "TBD", note = "use to_vec instead")]
    pub fn to_bytes(self) -> Vec<u8> {
        self.to_vec()
    }

    /// Serializes the public key to bytes.
    #[allow(clippy::missing_panics_doc)]
    pub fn to_vec(self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_into(&mut buf).expect("vecs don't error");
        buf
    }

    /// Serializes the public key into a `SortKey`.
    ///
    /// `SortKey` is not too useful by itself, but it can be used to sort a
    /// `[PublicKey]` slice using `sort_unstable_by_key`, `sort_by_cached_key`,
    /// `sort_by_key`, or any of the other `*_by_key` methods on slice.
    /// Pass the method into the sort method directly. (ie. `PublicKey::to_sort_key`)
    ///
    /// This method of sorting is in line with Bitcoin Core's implementation of
    /// sorting keys for output descriptors such as `sortedmulti()`.
    ///
    /// If every `PublicKey` in the slice is `compressed == true` then this will sort
    /// the keys in a
    /// [BIP-0067](https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki)
    /// compliant way.
    ///
    /// # Example: Using with `sort_unstable_by_key`
    ///
    /// ```rust
    /// use tidecoin::PublicKey;
    ///
    /// let pk = |s: &str| s.parse::<PublicKey>().unwrap();
    ///
    /// let mut unsorted = [
    ///     pk("04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc38e98ac269ffe028345c31ac8d0a365f29c8f7e7cfccac72f84e1acd02bc554f35"),
    ///     pk("038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354"),
    ///     pk("028bde91b10013e08949a318018fedbd896534a549a278e220169ee2a36517c7aa"),
    ///     pk("04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc3816753d96001fd7cba3ce5372f5c9a0d63708183033538d07b1e532fc43aaacfa"),
    ///     pk("032b8324c93575034047a52e9bca05a46d8347046b91a032eff07d5de8d3f2730b"),
    ///     pk("045d753414fa292ea5b8f56e39cfb6a0287b2546231a5cb05c4b14ab4b463d171f5128148985b23eccb1e2905374873b1f09b9487f47afa6b1f2b0083ac8b4f7e8"),
    ///     pk("0234dd69c56c36a41230d573d68adeae0030c9bc0bf26f24d3e1b64c604d293c68"),
    /// ];
    /// let sorted = [
    ///     // These first 4 keys are in a BIP-0067 compatible sorted order
    ///     // (since they are compressed)
    ///     pk("0234dd69c56c36a41230d573d68adeae0030c9bc0bf26f24d3e1b64c604d293c68"),
    ///     pk("028bde91b10013e08949a318018fedbd896534a549a278e220169ee2a36517c7aa"),
    ///     pk("032b8324c93575034047a52e9bca05a46d8347046b91a032eff07d5de8d3f2730b"),
    ///     pk("038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354"),
    ///     // Uncompressed keys are not BIP-0067 compliant, but are sorted
    ///     // after compressed keys in Bitcoin Core using `sortedmulti()`
    ///     pk("045d753414fa292ea5b8f56e39cfb6a0287b2546231a5cb05c4b14ab4b463d171f5128148985b23eccb1e2905374873b1f09b9487f47afa6b1f2b0083ac8b4f7e8"),
    ///     pk("04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc3816753d96001fd7cba3ce5372f5c9a0d63708183033538d07b1e532fc43aaacfa"),
    ///     pk("04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc38e98ac269ffe028345c31ac8d0a365f29c8f7e7cfccac72f84e1acd02bc554f35"),
    /// ];
    ///
    /// unsorted.sort_unstable_by_key(|k| PublicKey::to_sort_key(*k));
    ///
    /// assert_eq!(unsorted, sorted);
    /// ```
    pub fn to_sort_key(self) -> SortKey {
        let buf = self.with_serialized(ArrayVec::from_slice);
        SortKey(buf)
    }

    /// Deserializes a public key from a slice.
    ///
    /// # Errors
    ///
    /// * [`FromSliceError::InvalidLength`] if the slice has an invalid number of bytes.
    /// * [`FromSliceError::InvalidKeyPrefix`] if the key prefix is invalid.
    /// * [`FromSliceError::Secp256k1`] if the provided bytes do not form a valid public key.
    pub fn from_slice(data: &[u8]) -> Result<Self, FromSliceError> {
        let compressed = match data.len() {
            33 => true,
            65 => false,
            len => {
                return Err(FromSliceError::InvalidLength(len));
            }
        };

        // Compressed keys must have a prefix byte of 2 or 3. Uncompressed must be 4
        match (compressed, data[0]) {
            (true, 0x02) => (),
            (true, 0x03) => (),
            (false, 0x04) => (),
            (_, byte) => return Err(FromSliceError::InvalidKeyPrefix(byte)),
        }

        Ok(match compressed {
            true => Self::from_secp(secp256k1::PublicKey::from_slice(data)?),
            false => Self::from_secp_uncompressed(secp256k1::PublicKey::from_slice(data)?),
        })
    }

    /// Computes the public key as supposed to be used with this secret.
    pub fn from_private_key(sk: &PrivateKey) -> Self {
        sk.to_public_key()
    }

    /// Extracts the public key from a Keypair
    pub fn from_keypair(pair: &Keypair) -> Self {
        CompressedPublicKey::from_keypair(pair).into()
    }

    /// Checks that `sig` is a valid ECDSA signature for `msg` using this public key.
    ///
    /// # Errors
    ///
    /// [`secp256k1::Error::InvalidSignature`] if the signature is not valid for the given
    /// [`Message`].
    ///
    /// [`Message`]: secp256k1::Message
    pub fn verify(
        &self,
        msg: secp256k1::Message,
        sig: ecdsa::Signature,
    ) -> Result<(), secp256k1::Error> {
        secp256k1::ecdsa::verify(&sig.signature, msg, &self.to_inner())
    }
}

impl From<secp256k1::PublicKey> for PublicKey {
    fn from(pk: secp256k1::PublicKey) -> Self {
        Self::from_secp(pk)
    }
}

impl From<PublicKey> for XOnlyPublicKey {
    fn from(pk: PublicKey) -> Self {
        let (xonly, parity) = pk.to_inner().x_only_public_key();
        Self::from_secp(xonly, parity)
    }
}

/// An opaque return type for [`PublicKey::to_sort_key`].
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct SortKey(ArrayVec<u8, 65>);

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.with_serialized(|bytes| fmt::Display::fmt(&bytes.as_hex(), f))
    }
}

impl FromStr for PublicKey {
    type Err = ParsePublicKeyError;
    fn from_str(s: &str) -> Result<Self, ParsePublicKeyError> {
        match s.len() {
            66 => {
                let bytes = hex::decode_to_array::<33>(s).map_err(|e| match e {
                    DecodeFixedLengthBytesError::InvalidChar(e) => {
                        ParsePublicKeyError::InvalidChar(e)
                    }
                    DecodeFixedLengthBytesError::InvalidLength(_) => {
                        unreachable!("length checked already")
                    }
                })?;
                Ok(Self::from_slice(&bytes)?)
            }
            130 => {
                let bytes = hex::decode_to_array::<65>(s).map_err(|e| match e {
                    DecodeFixedLengthBytesError::InvalidChar(e) => {
                        ParsePublicKeyError::InvalidChar(e)
                    }
                    DecodeFixedLengthBytesError::InvalidLength(_) => {
                        unreachable!("length checked already")
                    }
                })?;
                Ok(Self::from_slice(&bytes)?)
            }
            len => Err(ParsePublicKeyError::InvalidHexLength(len)),
        }
    }
}

hashes::hash_newtype! {
    /// A hash of a public key.
    pub struct PubkeyHash(hash160::Hash);
    /// SegWit version of a public key hash.
    pub struct WPubkeyHash(hash160::Hash);
}

hashes::impl_hex_for_newtype!(PubkeyHash, WPubkeyHash);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(PubkeyHash, WPubkeyHash);

impl_asref_push_bytes!(PubkeyHash, WPubkeyHash);

impl From<PublicKey> for PubkeyHash {
    fn from(key: PublicKey) -> Self {
        key.pubkey_hash()
    }
}

impl From<&PublicKey> for PubkeyHash {
    fn from(key: &PublicKey) -> Self {
        key.pubkey_hash()
    }
}

impl CompressedPublicKey {
    /// Returns bitcoin 160-bit hash of the public key.
    pub fn pubkey_hash(&self) -> PubkeyHash {
        PubkeyHash(hash160::Hash::hash(&self.to_bytes()))
    }

    /// Returns bitcoin 160-bit hash of the public key for witness program.
    pub fn wpubkey_hash(&self) -> WPubkeyHash {
        WPubkeyHash::from_byte_array(hash160::Hash::hash(&self.to_bytes()).to_byte_array())
    }

    /// Returns the script code used to spend a P2WPKH input.
    ///
    /// While the type returned is [`WitnessScriptBuf`], this is **not** a witness script and
    /// should not be used as one. It is a special template defined in BIP 143 which is used
    /// in place of a witness script for purposes of sighash computation.
    pub fn p2wpkh_script_code(&self) -> WitnessScriptBuf {
        script::p2wpkh_script_code(self.wpubkey_hash())
    }

    /// Writes the public key into a writer.
    ///
    /// # Errors
    ///
    /// Errors if the bytes fail to write to the provided writer.
    pub fn write_into<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
        writer.write_all(&self.to_bytes())
    }

    /// Reads the public key from a reader.
    ///
    /// This internally reads the first byte before reading the rest, so
    /// use of a `BufReader` is recommended.
    ///
    /// # Errors
    ///
    /// Errors if the reader fails to read, or the read bytes are not a valid public key.
    pub fn read_from<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, io::Error> {
        let mut bytes = [0; 33];

        reader.read_exact(&mut bytes)?;
        #[allow(unused_variables)] // e when std not enabled
        Self::from_bytes(bytes).map_err(|e| {
            // Need a static string for no-std io
            #[cfg(feature = "std")]
            let reason = e;
            #[cfg(not(feature = "std"))]
            let reason = "secp256k1 error";
            io::Error::new(io::ErrorKind::InvalidData, reason)
        })
    }

    /// Serializes the public key.
    ///
    /// As the type name suggests, the key is serialized in compressed format.
    ///
    /// Note that this can be used as a sort key to get BIP-0067-compliant sorting.
    /// That's why this type doesn't have the `to_sort_key` method - it would duplicate this one.
    pub fn to_bytes(self) -> [u8; 33] {
        self.to_inner().serialize()
    }

    /// Deserializes a public key from a slice.
    ///
    /// # Errors
    ///
    /// See [`secp256k1::PublicKey::from_slice`].
    #[deprecated(
        since = "TBD",
        note = "use `from_bytes` instead; if you only have a slice, use `<&[u8; 33]>::try_from` first"
    )]
    pub fn from_slice(data: &[u8]) -> Result<Self, secp256k1::Error> {
        let bytes_arr = data.try_into().map_err(|_| secp256k1::Error::InvalidPublicKey)?;
        Self::from_bytes(bytes_arr)
    }

    /// Deserializes a public key from compressed pubkey bytes.
    ///
    /// # Errors
    ///
    /// See [`secp256k1::PublicKey::from_byte_array_compressed`].
    pub fn from_bytes(data: [u8; 33]) -> Result<Self, secp256k1::Error> {
        secp256k1::PublicKey::from_byte_array_compressed(data).map(Self::from_secp)
    }

    /// Computes the public key as supposed to be used with this secret.
    ///
    /// # Errors
    ///
    /// Errors if the private key is not compressed.
    pub fn from_private_key(sk: PrivateKey) -> Result<Self, UncompressedPublicKeyError> {
        sk.to_public_key().try_into()
    }

    /// Extracts the public key from a Keypair
    pub fn from_keypair(pair: &Keypair) -> Self {
        Self::from_secp(secp256k1::PublicKey::from_keypair(pair.as_inner()))
    }

    /// Checks that `sig` is a valid ECDSA signature for `msg` using this public key.
    ///
    /// # Errors
    ///
    /// See [`PublicKey::verify`].
    pub fn verify(
        &self,
        msg: secp256k1::Message,
        sig: ecdsa::Signature,
    ) -> Result<(), secp256k1::Error> {
        Ok(secp256k1::ecdsa::verify(&sig.signature, msg, &self.to_inner())?)
    }
}

impl fmt::Display for CompressedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.to_bytes().as_hex(), f)
    }
}

impl fmt::Debug for CompressedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_fmt(format_args!("CompressedPublicKey({})", self))
    }
}

impl FromStr for CompressedPublicKey {
    type Err = ParseCompressedPublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_bytes(hex::decode_to_array::<33>(s)?).map_err(Into::into)
    }
}

impl TryFrom<PublicKey> for CompressedPublicKey {
    type Error = UncompressedPublicKeyError;

    fn try_from(value: PublicKey) -> Result<Self, Self::Error> {
        if value.compressed() {
            Ok(Self::from_secp(value.to_inner()))
        } else {
            Err(UncompressedPublicKeyError)
        }
    }
}

impl From<secp256k1::PublicKey> for CompressedPublicKey {
    fn from(pk: secp256k1::PublicKey) -> Self {
        Self::from_secp(pk)
    }
}

impl From<CompressedPublicKey> for PublicKey {
    fn from(value: CompressedPublicKey) -> Self {
        Self::from_secp(value.to_inner())
    }
}

impl From<CompressedPublicKey> for XOnlyPublicKey {
    fn from(pk: CompressedPublicKey) -> Self {
        pk.to_inner().into()
    }
}

impl From<CompressedPublicKey> for PubkeyHash {
    fn from(key: CompressedPublicKey) -> Self {
        key.pubkey_hash()
    }
}

impl From<&CompressedPublicKey> for PubkeyHash {
    fn from(key: &CompressedPublicKey) -> Self {
        key.pubkey_hash()
    }
}

impl From<CompressedPublicKey> for WPubkeyHash {
    fn from(key: CompressedPublicKey) -> Self {
        key.wpubkey_hash()
    }
}

impl From<&CompressedPublicKey> for WPubkeyHash {
    fn from(key: &CompressedPublicKey) -> Self {
        key.wpubkey_hash()
    }
}

impl PrivateKey {
    /// Constructs a new compressed ECDSA private key using the secp256k1 algorithm and
    /// a secure random number generator.
    #[cfg(all(feature = "rand", feature = "std"))]
    pub fn generate() -> Self {
        let secret_key = secp256k1::SecretKey::new(&mut rand::rng());
        Self::from_secp(secret_key)
    }

    /// Constructs a new public key from this private key.
    pub fn to_public_key(&self) -> PublicKey {
        match self.compressed() {
            true => PublicKey::from_secp(secp256k1::PublicKey::from_secret_key(self.as_inner())),
            false => PublicKey::from_secp_uncompressed(secp256k1::PublicKey::from_secret_key(
                self.as_inner(),
            )),
        }
    }

    /// Constructs a new public key from this private key.
    #[deprecated(since = "TBD", note = "use `to_public_key` instead")]
    pub fn public_key(&self) -> PublicKey {
        self.to_public_key()
    }

    /// Serializes the private key to bytes.
    #[deprecated(since = "TBD", note = "use to_secret_vec instead")]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_secret_vec()
    }

    /// Serializes the private key to bytes.
    pub fn to_secret_vec(&self) -> Vec<u8> {
        self.to_secret_bytes().to_vec()
    }

    /// Serializes the private key to bytes.
    pub fn to_secret_bytes(&self) -> [u8; 32] {
        self.as_inner().to_secret_bytes()
    }

    /// Deserializes a private key from a byte array.
    ///
    /// # Errors
    ///
    /// Errors when the secret key is invalid: when it is all-zeros or would exceed
    /// the curve order when interpreted as a big-endian unsigned integer.
    pub fn from_secret_bytes(data: [u8; 32]) -> Result<Self, secp256k1::Error> {
        Ok(Self::from_secp(secp256k1::SecretKey::from_secret_bytes(data)?))
    }

    /// Deserializes a private key from a slice.
    ///
    /// # Errors
    ///
    /// [`secp256k1::Error::InvalidSecretKey`] if the slice is not 32 bytes long.
    /// See [`from_secret_bytes`] for other errors.
    ///
    /// [`from_secret_bytes`]: PrivateKey::from_secret_bytes
    #[deprecated(since = "TBD", note = "use from_secret_bytes instead")]
    pub fn from_slice(
        data: &[u8],
        _network: impl Into<NetworkKind>,
    ) -> Result<Self, secp256k1::Error> {
        let array = data.try_into().map_err(|_| secp256k1::Error::InvalidSecretKey)?;
        Self::from_secret_bytes(array)
    }

    /// Returns a new private key with the negated secret value.
    ///
    /// The resulting key corresponds to the same x-only public key (identical x-coordinate)
    /// but with the opposite y-coordinate parity. This is useful for ensuring compatibility
    /// with specific public key formats and BIP-0340 requirements.
    #[inline]
    pub fn negate(&self) -> Self {
        match self.compressed() {
            true => Self::from_secp(self.as_inner().negate()),
            false => Self::from_secp_uncompressed(self.as_inner().negate()),
        }
    }

    /// ECDSA signs a [`Message`] with this private key.
    ///
    /// This produces an ECDSA signature with a recovery ID for pubkey recovery.
    /// See [`RecoverableSignature::sign_ecdsa_recoverable`] for details.
    ///
    /// [`Message`]: secp256k1::Message
    /// [`RecoverableSignature::sign_ecdsa_recoverable`]: secp256k1::ecdsa::RecoverableSignature::sign_ecdsa_recoverable
    #[inline]
    #[cfg(feature = "secp-recovery")]
    pub fn raw_ecdsa_sign_recoverable(
        &self,
        msg: impl Into<secp256k1::Message>,
    ) -> MessageSignature {
        MessageSignature::new(
            secp256k1::ecdsa::RecoverableSignature::sign_ecdsa_recoverable(msg, self.as_inner()),
            self.compressed(),
        )
    }
}

/// A Bitcoin ECDSA private key with known network for WIF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifKey {
    /// The actual key
    pub private_key: PrivateKey,
    /// The network kind on which this key should be used.
    ///
    /// Regtest keys intentionally report [`NetworkKind::Test`] here. Use [`WifKey::network`] when
    /// the exact network matters for WIF round-tripping.
    pub network_kind: NetworkKind,
    network: Network,
}

/// Converts WIF network inputs into an exact Tidecoin network.
#[doc(hidden)]
pub trait IntoWifNetwork {
    /// Converts this value into the exact Tidecoin network used for WIF encoding.
    #[doc(hidden)]
    fn into_wif_network(self) -> Network;
}

impl IntoWifNetwork for Network {
    fn into_wif_network(self) -> Network {
        self
    }
}

impl IntoWifNetwork for NetworkKind {
    fn into_wif_network(self) -> Network {
        match self {
            Self::Main => Network::Tidecoin,
            Self::Test => Network::Testnet,
        }
    }
}

#[inline]
fn wif_network_prefix(network: Network) -> u8 {
    match network {
        Network::Tidecoin => 125,
        Network::Testnet => 180,
        Network::Regtest => 15,
    }
}

fn parse_wif_network_prefix(prefix: u8) -> Result<Network, InvalidAddressVersionError> {
    match prefix {
        125 => Ok(Network::Tidecoin),
        180 => Ok(Network::Testnet),
        15 => Ok(Network::Regtest),
        invalid => Err(InvalidAddressVersionError { invalid }),
    }
}

impl WifKey {
    /// Constructs a new WIF private key from the provided [`PrivateKey`] and the
    /// specified network.
    pub fn new(key: PrivateKey, network: impl IntoWifNetwork) -> Self {
        let network = network.into_wif_network();
        Self { network_kind: NetworkKind::from(network), network, private_key: key }
    }

    /// Returns the exact network carried by this WIF key.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Formats the private key to WIF format.
    ///
    /// # Errors
    ///
    /// Errors if `fmt` cannot be written to.
    #[rustfmt::skip]
    pub fn fmt_wif(&self, fmt: &mut dyn fmt::Write) -> fmt::Result {
        let mut ret = [0; 34];
        ret[0] = wif_network_prefix(self.network);

        ret[1..33].copy_from_slice(&self.private_key.as_inner()[..]);
        let privkey = if self.private_key.compressed() {
            ret[33] = 1;
            base58::encode_check(&ret[..])
        } else {
            base58::encode_check(&ret[..33])
        };
        fmt.write_str(&privkey)
    }

    /// Gets the WIF encoding of this private key.
    pub fn to_wif(&self) -> String {
        let mut buf = String::new();
        let _ = self.fmt_wif(&mut buf);
        buf.shrink_to_fit();
        buf
    }

    /// Parses the WIF encoded private key.
    ///
    /// # Errors
    ///
    /// * [`FromWifError::Base58`] if the string is not a valid base58 encoded string.
    /// * [`FromWifError::InvalidBase58PayloadLength`] if the decoded base58 data is not 33 or 34
    ///   bytes long.
    /// * [`FromWifError::InvalidWifCompressionFlag`] if the compression flag is not 1 for a 34 byte
    ///   data string.
    /// * [`FromWifError::InvalidAddressVersion`] if the network version byte is not recognized for
    ///   Tidecoin mainnet, testnet, or regtest.
    /// * [`FromWifError::Secp256k1`] if the bytes are not representative of a valid private key.
    pub fn from_wif(wif: &str) -> Result<Self, FromWifError> {
        let data = base58::decode_check(wif)?;

        let (compressed, data) = if let Ok(data) = <&[u8; 33]>::try_from(&*data) {
            (false, data)
        } else if let Ok(data) = <&[u8; 34]>::try_from(&*data) {
            let (compressed_flag, data) = data.split_last::<33>();
            if *compressed_flag != 1 {
                return Err(InvalidWifCompressionFlagError { invalid: *compressed_flag }.into());
            }
            (true, data)
        } else {
            return Err(InvalidBase58PayloadLengthError { length: data.len() }.into());
        };

        let (network, key) = data.split_first();
        let network = parse_wif_network_prefix(*network)?;

        let sec_key = secp256k1::SecretKey::from_secret_bytes(*key)?;
        let priv_key = match compressed {
            true => PrivateKey::from_secp(sec_key),
            false => PrivateKey::from_secp_uncompressed(sec_key),
        };
        Ok(Self::new(priv_key, network))
    }
}

// [`WifKey`] intentionally has a `FromStr` without a reciprocal `Display`.
// Parsing from a WIF string should be convenient, printing secret data should not.
impl FromStr for WifKey {
    type Err = FromWifError;
    fn from_str(s: &str) -> Result<Self, FromWifError> {
        Self::from_wif(s)
    }
}

/// Encodes how a [`PqWifKey`] should be serialized to base58.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum PqWifFormat {
    /// Tidecoin node's current PQ secret format: `[network_prefix][scheme_prefix][raw_secret]`.
    Prefixed,
    /// Tidecoin node's legacy Falcon-512 format:
    /// `[network_prefix][raw_falcon512_secret][0x01][prefixed_pubkey]`.
    LegacyFalcon512,
}

/// A Tidecoin PQ private key with node-compatible base58 import/export.
///
/// This mirrors Tidecoin node's `EncodeSecret` / `DecodeSecret` handling for PQ secret keys.
/// The supported encodings are:
/// - the current prefixed format for all five PQ schemes
/// - the legacy Falcon-512-only format used by old Tidecoin WIF toolpaths
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqWifKey {
    /// The PQ secret key carried by this WIF payload.
    pub secret_key: PqSecretKey,
    /// The public key matching `secret_key`.
    pub public_key: PqPublicKey,
    /// The network kind on which this key should be used.
    ///
    /// Regtest keys intentionally report [`NetworkKind::Test`] here. Use [`PqWifKey::network`] when
    /// the exact network matters for WIF round-tripping.
    pub network_kind: NetworkKind,
    network: Network,
    format: PqWifFormat,
}

impl PqWifKey {
    fn with_format(
        secret_key: PqSecretKey,
        public_key: PqPublicKey,
        network: impl IntoWifNetwork,
        format: PqWifFormat,
    ) -> Self {
        let network = network.into_wif_network();
        Self { network_kind: NetworkKind::from(network), network, secret_key, public_key, format }
    }

    /// Constructs a new PQ WIF key using Tidecoin node's current prefixed secret format.
    pub fn new(secret_key: PqSecretKey, network: impl IntoWifNetwork) -> Result<Self, PqError> {
        let public_key = PqPublicKey::from_secret_key(&secret_key)?;
        Ok(Self::with_format(secret_key, public_key, network, PqWifFormat::Prefixed))
    }

    /// Constructs a new PQ WIF key using Tidecoin node's legacy Falcon-512 format.
    pub fn new_legacy_falcon512(
        secret_key: PqSecretKey,
        network: impl IntoWifNetwork,
    ) -> Result<Self, FromPqWifError> {
        if secret_key.scheme() != PqScheme::Falcon512 {
            return Err(UnsupportedLegacyWifSchemeError { scheme: secret_key.scheme() }.into());
        }
        let public_key = PqPublicKey::from_secret_key(&secret_key)?;
        Ok(Self::with_format(secret_key, public_key, network, PqWifFormat::LegacyFalcon512))
    }

    /// Returns the exact network carried by this WIF key.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Returns the serialization format this key will use.
    pub fn format(&self) -> PqWifFormat {
        self.format
    }

    /// Formats the key to Tidecoin node's base58 secret format.
    pub fn fmt_wif(&self, fmt: &mut dyn fmt::Write) -> fmt::Result {
        let mut data = Vec::with_capacity(
            1 + self.secret_key.to_prefixed_bytes().len()
                + self.public_key.to_prefixed_bytes().len(),
        );
        data.push(wif_network_prefix(self.network));
        match self.format {
            PqWifFormat::Prefixed => {
                data.extend_from_slice(&self.secret_key.to_prefixed_bytes());
            }
            PqWifFormat::LegacyFalcon512 => {
                debug_assert_eq!(self.secret_key.scheme(), PqScheme::Falcon512);
                data.extend_from_slice(self.secret_key.as_bytes());
                data.push(1);
                data.extend_from_slice(&self.public_key.to_prefixed_bytes());
            }
        }
        fmt.write_str(&base58::encode_check(&data))
    }

    /// Gets the Tidecoin node-compatible base58 encoding of this PQ private key.
    pub fn to_wif(&self) -> String {
        let mut buf = String::new();
        let _ = self.fmt_wif(&mut buf);
        buf.shrink_to_fit();
        buf
    }

    /// Parses the Tidecoin node-compatible base58 PQ secret format.
    pub fn from_wif(wif: &str) -> Result<Self, FromPqWifError> {
        let data = base58::decode_check(wif)?;
        if data.len() < 2 {
            return Err(InvalidBase58PayloadLengthError { length: data.len() }.into());
        }

        let (&network_prefix, payload) = data
            .split_first()
            .ok_or(InvalidBase58PayloadLengthError { length: data.len() })?;
        let network = parse_wif_network_prefix(network_prefix)?;

        let legacy_scheme = PqScheme::Falcon512;
        let legacy_total_len = legacy_scheme.seckey_len() + 1 + legacy_scheme.prefixed_pubkey_len();
        if payload.len() == legacy_total_len && payload[legacy_scheme.seckey_len()] == 1 {
            let secret_key =
                PqSecretKey::decode_slice(&payload[..legacy_scheme.seckey_len()], true)?;
            if secret_key.scheme() != legacy_scheme {
                return Err(UnsupportedLegacyWifSchemeError { scheme: secret_key.scheme() }.into());
            }
            let public_key =
                PqPublicKey::from_prefixed_slice(&payload[legacy_scheme.seckey_len() + 1..])?;
            let derived = PqPublicKey::from_secret_key(&secret_key)?;
            if public_key != derived {
                return Err(MismatchedPqPublicKeyError.into());
            }
            return Ok(Self::with_format(
                secret_key,
                public_key,
                network,
                PqWifFormat::LegacyFalcon512,
            ));
        }

        let secret_key = PqSecretKey::from_prefixed_slice(payload)?;
        let public_key = PqPublicKey::from_secret_key(&secret_key)?;
        Ok(Self::with_format(secret_key, public_key, network, PqWifFormat::Prefixed))
    }
}

impl FromStr for PqWifKey {
    type Err = FromPqWifError;
    fn from_str(s: &str) -> Result<Self, FromPqWifError> {
        Self::from_wif(s)
    }
}

/// Error generated from PQ WIF key format.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FromPqWifError {
    /// A base58 decoding error.
    Base58(base58::Error),
    /// Base58 decoded data was an invalid length.
    InvalidBase58PayloadLength(InvalidBase58PayloadLengthError),
    /// Base58 decoded data contained an invalid address version byte.
    InvalidAddressVersion(InvalidAddressVersionError),
    /// PQ key decoding or validation failed.
    Pq(PqError),
    /// Legacy PQ WIF is only defined for Falcon-512.
    UnsupportedLegacyWifScheme(UnsupportedLegacyWifSchemeError),
    /// Legacy PQ WIF carried a public key that does not match the secret key.
    MismatchedPublicKey(MismatchedPqPublicKeyError),
}

impl From<Infallible> for FromPqWifError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl fmt::Display for FromPqWifError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Base58(ref e) => write_err!(f, "invalid base58"; e),
            Self::InvalidBase58PayloadLength(ref e) => {
                write_err!(f, "decoded base58 data was an invalid length"; e)
            }
            Self::InvalidAddressVersion(ref e) => {
                write_err!(f, "decoded base58 data contained an invalid address version byte"; e)
            }
            Self::Pq(ref e) => write_err!(f, "PQ private key validation failed"; e),
            Self::UnsupportedLegacyWifScheme(ref e) => {
                write_err!(f, "unsupported legacy PQ WIF scheme"; e)
            }
            Self::MismatchedPublicKey(ref e) => {
                write_err!(f, "legacy PQ WIF public key does not match secret key"; e)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromPqWifError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Base58(ref e) => Some(e),
            Self::InvalidBase58PayloadLength(ref e) => Some(e),
            Self::InvalidAddressVersion(ref e) => Some(e),
            Self::Pq(ref e) => Some(e),
            Self::UnsupportedLegacyWifScheme(ref e) => Some(e),
            Self::MismatchedPublicKey(ref e) => Some(e),
        }
    }
}

impl From<base58::Error> for FromPqWifError {
    fn from(e: base58::Error) -> Self {
        Self::Base58(e)
    }
}

impl From<PqError> for FromPqWifError {
    fn from(e: PqError) -> Self {
        Self::Pq(e)
    }
}

impl From<InvalidBase58PayloadLengthError> for FromPqWifError {
    fn from(e: InvalidBase58PayloadLengthError) -> Self {
        Self::InvalidBase58PayloadLength(e)
    }
}

impl From<InvalidAddressVersionError> for FromPqWifError {
    fn from(e: InvalidAddressVersionError) -> Self {
        Self::InvalidAddressVersion(e)
    }
}

impl From<UnsupportedLegacyWifSchemeError> for FromPqWifError {
    fn from(e: UnsupportedLegacyWifSchemeError) -> Self {
        Self::UnsupportedLegacyWifScheme(e)
    }
}

impl From<MismatchedPqPublicKeyError> for FromPqWifError {
    fn from(e: MismatchedPqPublicKeyError) -> Self {
        Self::MismatchedPublicKey(e)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for WifKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_wif())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for WifKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct WifVisitor;

        impl serde::de::Visitor<'_> for WifVisitor {
            type Value = WifKey;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("an ASCII WIF string")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if let Ok(s) = core::str::from_utf8(v) {
                    s.parse::<WifKey>().map_err(E::custom)
                } else {
                    Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                }
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v.parse::<WifKey>().map_err(E::custom)
            }
        }

        d.deserialize_str(WifVisitor)
    }
}

#[cfg(feature = "serde")]
#[allow(clippy::collapsible_else_if)] // Aids readability.
impl serde::Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            self.with_serialized(|bytes| s.serialize_bytes(bytes))
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            struct HexVisitor;

            impl serde::de::Visitor<'_> for HexVisitor {
                type Value = PublicKey;

                fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                    formatter.write_str("an ASCII hex string")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    if let Ok(hex) = core::str::from_utf8(v) {
                        hex.parse::<PublicKey>().map_err(E::custom)
                    } else {
                        Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                    }
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    v.parse::<PublicKey>().map_err(E::custom)
                }
            }
            d.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;

            impl serde::de::Visitor<'_> for BytesVisitor {
                type Value = PublicKey;

                fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                    formatter.write_str("a bytestring")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    PublicKey::from_slice(v).map_err(E::custom)
                }
            }

            d.deserialize_bytes(BytesVisitor)
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for CompressedPublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.to_bytes())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for CompressedPublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            struct HexVisitor;

            impl serde::de::Visitor<'_> for HexVisitor {
                type Value = CompressedPublicKey;

                fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                    formatter.write_str("a 66 digits long ASCII hex string")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    if let Ok(hex) = core::str::from_utf8(v) {
                        hex.parse::<CompressedPublicKey>().map_err(E::custom)
                    } else {
                        Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                    }
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    v.parse::<CompressedPublicKey>().map_err(E::custom)
                }
            }
            d.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;

            impl serde::de::Visitor<'_> for BytesVisitor {
                type Value = CompressedPublicKey;

                fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                    formatter.write_str("a bytestring")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    let arr = v.try_into().map_err(E::custom)?;
                    CompressedPublicKey::from_bytes(arr).map_err(E::custom)
                }
            }

            d.deserialize_bytes(BytesVisitor)
        }
    }
}
/// Error returned while generating key from slice.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FromSliceError {
    /// Invalid key prefix error.
    InvalidKeyPrefix(u8),
    /// A secp256k1 error.
    Secp256k1(secp256k1::Error),
    /// Invalid Length of the slice.
    InvalidLength(usize),
}

impl From<Infallible> for FromSliceError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl fmt::Display for FromSliceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Secp256k1(e) => write_err!(f, "secp256k1"; e),
            Self::InvalidKeyPrefix(b) => write!(f, "key prefix invalid: {}", b),
            Self::InvalidLength(got) => {
                write!(f, "slice length should be 33 or 65 bytes, got: {}", got)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromSliceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Secp256k1(ref e) => Some(e),
            Self::InvalidKeyPrefix(_) | Self::InvalidLength(_) => None,
        }
    }
}

impl From<secp256k1::Error> for FromSliceError {
    fn from(e: secp256k1::Error) -> Self {
        Self::Secp256k1(e)
    }
}

/// Error generated from WIF key format.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FromWifError {
    /// A base58 decoding error.
    Base58(base58::Error),
    /// Base58 decoded data was an invalid length.
    InvalidBase58PayloadLength(InvalidBase58PayloadLengthError),
    /// Base58 decoded data contained an invalid address version byte.
    InvalidAddressVersion(InvalidAddressVersionError),
    /// A secp256k1 error.
    Secp256k1(secp256k1::Error),
    /// Invalid WIF compression flag.
    InvalidWifCompressionFlag(InvalidWifCompressionFlagError),
}

impl From<Infallible> for FromWifError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl fmt::Display for FromWifError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Base58(ref e) => write_err!(f, "invalid base58"; e),
            Self::InvalidBase58PayloadLength(ref e) => {
                write_err!(f, "decoded base58 data was an invalid length"; e)
            }
            Self::InvalidAddressVersion(ref e) => {
                write_err!(f, "decoded base58 data contained an invalid address version byte"; e)
            }
            Self::Secp256k1(ref e) => write_err!(f, "private key validation failed"; e),
            Self::InvalidWifCompressionFlag(ref e) => {
                write_err!(f, "invalid WIF compression flag"; e)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromWifError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Base58(ref e) => Some(e),
            Self::InvalidBase58PayloadLength(ref e) => Some(e),
            Self::InvalidAddressVersion(ref e) => Some(e),
            Self::Secp256k1(ref e) => Some(e),
            Self::InvalidWifCompressionFlag(ref e) => Some(e),
        }
    }
}

impl From<base58::Error> for FromWifError {
    fn from(e: base58::Error) -> Self {
        Self::Base58(e)
    }
}

impl From<secp256k1::Error> for FromWifError {
    fn from(e: secp256k1::Error) -> Self {
        Self::Secp256k1(e)
    }
}

impl From<InvalidBase58PayloadLengthError> for FromWifError {
    fn from(e: InvalidBase58PayloadLengthError) -> Self {
        Self::InvalidBase58PayloadLength(e)
    }
}

impl From<InvalidAddressVersionError> for FromWifError {
    fn from(e: InvalidAddressVersionError) -> Self {
        Self::InvalidAddressVersion(e)
    }
}

impl From<InvalidWifCompressionFlagError> for FromWifError {
    fn from(e: InvalidWifCompressionFlagError) -> Self {
        Self::InvalidWifCompressionFlag(e)
    }
}

/// Error returned while constructing a [`Keypair`] from string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseKeypairError(secp256k1::Error);

impl From<Infallible> for ParseKeypairError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl fmt::Display for ParseKeypairError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_err!(f, "parse keypair failed"; self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseKeypairError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Error returned while constructing public key from string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsePublicKeyError {
    /// Error originated while parsing string.
    Encoding(FromSliceError),
    /// Hex decoding error.
    InvalidChar(hex::error::InvalidCharError),
    /// `PublicKey` hex should be 66 or 130 digits long.
    InvalidHexLength(usize),
}

impl From<Infallible> for ParsePublicKeyError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl fmt::Display for ParsePublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Encoding(ref e) => write_err!(f, "string error"; e),
            Self::InvalidChar(ref e) => write_err!(f, "hex decoding"; e),
            Self::InvalidHexLength(got) => {
                write!(f, "pubkey string should be 66 or 130 digits long, got: {}", got)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParsePublicKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encoding(ref e) => Some(e),
            Self::InvalidChar(ref e) => Some(e),
            Self::InvalidHexLength(_) => None,
        }
    }
}

impl From<FromSliceError> for ParsePublicKeyError {
    fn from(e: FromSliceError) -> Self {
        Self::Encoding(e)
    }
}

/// Error returned when parsing a [`CompressedPublicKey`] from a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseCompressedPublicKeyError {
    /// secp256k1 Error.
    Secp256k1(secp256k1::Error),
    /// hex to array conversion error.
    Hex(hex::DecodeFixedLengthBytesError),
}

impl From<Infallible> for ParseCompressedPublicKeyError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

impl fmt::Display for ParseCompressedPublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Secp256k1(e) => write_err!(f, "secp256k1 error"; e),
            Self::Hex(e) => write_err!(f, "invalid hex"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseCompressedPublicKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Secp256k1(e) => Some(e),
            Self::Hex(e) => Some(e),
        }
    }
}

impl From<secp256k1::Error> for ParseCompressedPublicKeyError {
    fn from(e: secp256k1::Error) -> Self {
        Self::Secp256k1(e)
    }
}

impl From<hex::DecodeFixedLengthBytesError> for ParseCompressedPublicKeyError {
    fn from(e: hex::DecodeFixedLengthBytesError) -> Self {
        Self::Hex(e)
    }
}

/// SegWit public keys must always be compressed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UncompressedPublicKeyError;

impl fmt::Display for UncompressedPublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("SegWit public keys must always be compressed")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UncompressedPublicKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// Decoded base58 data was an invalid length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidBase58PayloadLengthError {
    /// The base58 payload length we got after decoding WIF string.
    pub(crate) length: usize,
}

impl InvalidBase58PayloadLengthError {
    /// Returns the invalid payload length.
    pub fn invalid_base58_payload_length(&self) -> usize {
        self.length
    }
}

impl fmt::Display for InvalidBase58PayloadLengthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "decoded base58 data was an invalid length: {} (expected 33 or 34)", self.length)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidBase58PayloadLengthError {}

/// Invalid address version in decoded base58 data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidAddressVersionError {
    /// The invalid version.
    pub(crate) invalid: u8,
}

impl InvalidAddressVersionError {
    /// Returns the invalid version.
    pub fn invalid_address_version(&self) -> u8 {
        self.invalid
    }
}

impl fmt::Display for InvalidAddressVersionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid address version in decoded base58 data {}", self.invalid)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidAddressVersionError {}

/// Invalid compression flag for a WIF key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidWifCompressionFlagError {
    /// The invalid compression flag.
    pub(crate) invalid: u8,
}

impl InvalidWifCompressionFlagError {
    /// Returns the invalid compression flag.
    pub fn invalid_compression_flag(&self) -> u8 {
        self.invalid
    }
}

impl fmt::Display for InvalidWifCompressionFlagError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid WIF compression flag. Expected a 0x01 byte at the end of the key but found: {}", self.invalid)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidWifCompressionFlagError {}

/// Legacy PQ WIF is only defined for Falcon-512.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedLegacyWifSchemeError {
    pub(crate) scheme: PqScheme,
}

impl UnsupportedLegacyWifSchemeError {
    /// Returns the unsupported PQ scheme found in the legacy WIF path.
    pub fn scheme(&self) -> PqScheme {
        self.scheme
    }
}

impl fmt::Display for UnsupportedLegacyWifSchemeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "legacy PQ WIF only supports Falcon-512, got {:?}", self.scheme)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnsupportedLegacyWifSchemeError {}

/// Legacy PQ WIF carried a public key that does not match the secret key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MismatchedPqPublicKeyError;

impl fmt::Display for MismatchedPqPublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("legacy PQ WIF public key does not match secret key")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MismatchedPqPublicKeyError {}

impl SerializedXOnlyPublicKey {
    /// Returns `XOnlyPublicKey` if the bytes are valid.
    ///
    /// # Errors
    ///
    /// [`ParseXOnlyPublicKeyError::InvalidXCoordinate`] if the provided bytes don't represent
    /// a valid secp256k1 point x-coordinate.
    pub fn to_validated(self) -> Result<XOnlyPublicKey, ParseXOnlyPublicKeyError> {
        XOnlyPublicKey::from_byte_array(self.as_byte_array())
    }
}

impl AsRef<[u8; 32]> for SerializedXOnlyPublicKey {
    fn as_ref(&self) -> &[u8; 32] {
        self.as_byte_array()
    }
}

impl From<&Self> for SerializedXOnlyPublicKey {
    fn from(borrowed: &Self) -> Self {
        *borrowed
    }
}

impl fmt::Debug for SerializedXOnlyPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.as_byte_array().as_hex(), f)
    }
}

/// Error that can occur when parsing an [`XOnlyPublicKey`] from bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseXOnlyPublicKeyError {
    /// The provided bytes do not represent a valid secp256k1 point x-coordinate.
    InvalidXCoordinate,
}

impl fmt::Display for ParseXOnlyPublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidXCoordinate => write!(f, "Invalid X coordinate for secp256k1 point"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseXOnlyPublicKeyError {}

/// Error that can occur when tweaking an [`XOnlyPublicKey`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TweakXOnlyPublicKeyError {
    /// The tweak value was invalid.
    BadTweak,
    /// The resulting public key would be invalid.
    ResultKeyInvalid,
    /// Invalid parity value encountered during the operation.
    ParityError,
}

impl fmt::Display for TweakXOnlyPublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::BadTweak => write!(f, "Invalid tweak value"),
            Self::ResultKeyInvalid => write!(f, "Resulting public key would be invalid"),
            Self::ParityError => write!(f, "Invalid parity value encountered"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TweakXOnlyPublicKeyError {}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for PublicKey {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from_secp(secp256k1::PublicKey::arbitrary(u)?))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for XOnlyPublicKey {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::from_secp(secp256k1::XOnlyPublicKey::arbitrary(u)?, u.arbitrary()?))
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    fn pq_seed_for(scheme: PqScheme, salt: u8) -> Vec<u8> {
        (0..scheme.deterministic_seed_len()).map(|i| salt.wrapping_add(i as u8)).collect()
    }

    #[test]
    fn wif_roundtrips_match_tidecoin_node_vectors() {
        let cases = [
            ("5D5GVU17zd3H6Ug9RUhW9AhHF517fWYnqmNpRRNQfjHhtbiN64U", Network::Tidecoin, false),
            ("Ke3QwMF5Hq4eTZCpuKo4Z5o7N5TfcymRQwJbyuGTeXvsLKMqm1pa", Network::Tidecoin, true),
            ("73shpPov4UmczPAa7nn1L145nNkT68HGCksBBigoMx4vc7wxcTq", Network::Testnet, false),
            ("Tkur1oTnuyNHxPkGqjUTqgU1uMDpUYUHuZCSsaY3h2qdN7pDd6TC", Network::Testnet, true),
            ("WM2W11ALsXGn3V2RQjKEXbLV21ABT6B4FLnVi821nRXDuZqoky", Network::Regtest, false),
            ("3Fqd6KuqiQcNaBPV1ZNpBwVqE9ApueF4zy2YsXKtnXaGVV4R2sE3", Network::Regtest, true),
        ];

        for (wif, network, compressed) in cases {
            let key = WifKey::from_wif(wif).unwrap();
            assert_eq!(key.network(), network);
            assert_eq!(key.network_kind, NetworkKind::from(network));
            assert_eq!(key.private_key.compressed(), compressed);
            assert_eq!(key.to_wif(), wif);
            assert_eq!(wif.parse::<WifKey>().unwrap(), key);
        }
    }

    #[test]
    fn pq_wif_roundtrips_prefixed_all_schemes() {
        let cases = [
            (PqScheme::Falcon512, Network::Tidecoin, 0x10),
            (PqScheme::Falcon1024, Network::Testnet, 0x20),
            (PqScheme::MlDsa44, Network::Regtest, 0x30),
            (PqScheme::MlDsa65, Network::Tidecoin, 0x40),
            (PqScheme::MlDsa87, Network::Testnet, 0x50),
        ];

        for (scheme, network, salt) in cases {
            let (_pk, sk) = scheme.generate_keypair_from_seed(&pq_seed_for(scheme, salt)).unwrap();
            let key = PqWifKey::new(sk.clone(), network).unwrap();
            let encoded = key.to_wif();
            let decoded = PqWifKey::from_wif(&encoded).unwrap();
            assert_eq!(decoded.network(), network);
            assert_eq!(decoded.network_kind, NetworkKind::from(network));
            assert_eq!(decoded.secret_key, sk);
            assert_eq!(decoded.public_key, PqPublicKey::from_secret_key(&sk).unwrap());
            assert_eq!(decoded.format(), PqWifFormat::Prefixed);
            assert_eq!(decoded.to_wif(), encoded);
            assert_eq!(encoded.parse::<PqWifKey>().unwrap(), decoded);
        }
    }

    #[test]
    fn pq_wif_roundtrips_prefixed_node_vector_used_by_legacy_signing_path() {
        let wif = "6ddD664vfvjyAquu3uNwVWehzSCoywRyjqo1EA9xdA2iQH8bBNYi7VNEPkqx7rm5b2pqUsDtu9YdwQ4rkHs2Xq5XzpLywUsYS7LeiZyBXmmmZ47q1zxB6b2N14PKvXfywgajjpxv7WFRAqtWDXi6uy5NVwsLn2KdJQybjQpMzX9772M1gCoc3EgBvwfin8c7aeeBdSWShh9gh5pbGTrcU2LeQPoWP4yTRhZ2sCxNuaJWaMPbjyhEf5QFBpXmLCtQQiGjSghttdLayrhBr3hw3ydGk4rwTTgv8MX68rZvnEEV3xibEG3ud8Rq7jGfumk4FaAEUdfiRdHZEZdBx4wDYaQurihxcm6EMCApZ9v1B68NNh4whtQLuHfsqod5ye8K9TPHWS19MtFT96dtdMuSB5CwvhL8Fa6TTjwPAGBYpU5xynym9bdMrZRMsUhTzAyoGmFD1sp94jUE46iwdfp7FFrboyPLV5zLiDfToKmM1J2343quyuzrTewmA6wdqUZbKAmhtL28pbDAoy6jMwk2TM1cggcFmSR3uSXcgDVnV7J9mTBmpvXDaN8xxG18JcSWSbewFVnHLCddvhPn2ZutGPpMRtDkMc3vWt5s9iD3gTUyWC9kjZsjc65Gd6t3JChSKDpUC5BGA5pdHBwo2P5j87DkZqcrUjpeMX25zgPMdt9ZWeRs6SUqJtTGMj4Hk1syNbovpm4Eqha66n8vTvVnwHrxvn85ds4ZcFpxv1FukG7TQ6iStJLBcmwcUSFtyvBFmbK9qu8ToXNGoPnqVCR8V6XveLPCfDELjHoCMCLnp4eQa3AwJpg9Pg9qVQjvcoHqD44JuZ86CAjLcyAmm9QnFcs3JX7JyLKCnBzj3DfjWr2SNgrhjiGnMBrykjEVX6vis6vDL9cJ56jTuxWDovhwzBr5VbkoBArh6MS6z1SPv6Xvv8Sj7ej3nRHZ31Gh5estzKzdUKSU2vQxmtd4Q6KqjjBSf6xLU1K1S9mAtqn3CzKMMDKeLFtTu1oFwHTGDqaCDmAKXWJX1o2xzmTdWCd3UHB9wobBjtjWUcNxvw4ig7BHW89JgsbfzRneyktwdk1cYWU52AHTdFUSnchYwQBPEqyJ5bD7zWo5AbVNMPrebEnt2Sb29CS2XYBwsD88hU6ka2BHmNmTGedEHJmhHzkrJkyWqFAkSZBsH5yq6x6ttYrDH8zXX7i98FzV2ZKnKuyy6NcgwpC8rYaMYPSie14DzoPfGUJc6BytBV69mZDsoJ2UUoVH94uiBkZUPTFfDcyCoDxBACCPxdCnJokerkAvDmFzujELyf2rK9nEoQeVdh9QJdYTTLAgJdzMyREHHYWyseWWti9n2gadocnRwiUMSqEt683KHiMW4Bn8AWBDSFQfXZYvVBcuEL4jvBSXMVJt4Z6cD11gqmCM9BgEGy2CoNLELVmRDRq3RMN22G2jX5U353eqikvgumub2sGRuErt3vbDuEELbmJAzLrVrXjfmbeU5ev5ZhMpBP7CiyRy7sk2DViDYDrZ9W5J8hPDRDVy7SV85bF1MHz1GjXjMjCMSSBYwvPTT9gd7Rmmc1MfVo26t6iS4YVdVeoCBGdvLdCUWd6Z8UZPmkpPASnVN3yj9m119DRyXsZUsqyeNF2vEDTVSNfjfofLGqfFmKtHDEkECW94huFapxokwmSvgi15sYiEKXBXknHnctaEiahSh7ha9qJ6UqhEnd7aJxzG1JbUerZbZMF4dxLEumd66ixzbgAWSBHoC1";
        let decoded = PqWifKey::from_wif(wif).unwrap();

        assert_eq!(decoded.network(), Network::Tidecoin);
        assert_eq!(decoded.network_kind, NetworkKind::Main);
        assert_eq!(decoded.format(), PqWifFormat::Prefixed);
        assert_eq!(decoded.secret_key.scheme(), PqScheme::Falcon512);
        assert_eq!(decoded.public_key, PqPublicKey::from_secret_key(&decoded.secret_key).unwrap());
        assert_eq!(decoded.to_wif(), wif);
        assert_eq!(wif.parse::<PqWifKey>().unwrap(), decoded);
    }

    #[test]
    fn pq_wif_new_legacy_rejects_non_falcon_schemes() {
        let scheme = PqScheme::MlDsa44;
        let (_pk, sk) = scheme.generate_keypair_from_seed(&pq_seed_for(scheme, 0x42)).unwrap();
        let err = PqWifKey::new_legacy_falcon512(sk, Network::Tidecoin).unwrap_err();

        assert_eq!(
            err,
            FromPqWifError::UnsupportedLegacyWifScheme(UnsupportedLegacyWifSchemeError { scheme })
        );
    }

    #[test]
    fn pq_wif_roundtrips_generated_legacy_falcon512() {
        let scheme = PqScheme::Falcon512;
        let (_pk, sk) = scheme.generate_keypair_from_seed(&pq_seed_for(scheme, 0x55)).unwrap();
        let key = PqWifKey::new_legacy_falcon512(sk.clone(), Network::Tidecoin).unwrap();
        let encoded = key.to_wif();
        let decoded = PqWifKey::from_wif(&encoded).unwrap();

        assert_eq!(decoded.network(), Network::Tidecoin);
        assert_eq!(decoded.network_kind, NetworkKind::Main);
        assert_eq!(decoded.secret_key, sk);
        assert_eq!(decoded.public_key, PqPublicKey::from_secret_key(&sk).unwrap());
        assert_eq!(decoded.format(), PqWifFormat::LegacyFalcon512);
        assert_eq!(decoded.to_wif(), encoded);
    }

    #[test]
    fn pq_wif_legacy_detects_mismatched_public_key() {
        let scheme = PqScheme::Falcon512;
        let (_pk, sk) = scheme.generate_keypair_from_seed(&pq_seed_for(scheme, 0x60)).unwrap();
        let key = PqWifKey::new_legacy_falcon512(sk, Network::Tidecoin).unwrap();
        let mut data = base58::decode_check(&key.to_wif()).unwrap();
        let pubkey_offset = 1 + key.secret_key.as_bytes().len() + 1;
        data[pubkey_offset + 1] ^= 0x01;
        let wif = base58::encode_check(&data);

        let err = PqWifKey::from_wif(&wif).unwrap_err();
        assert_eq!(err, FromPqWifError::MismatchedPublicKey(MismatchedPqPublicKeyError));
    }

    #[test]
    fn pubkey_hash() {
        let pk = "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
            .parse::<PublicKey>()
            .unwrap();
        let upk = "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133"
        .parse::<PublicKey>().unwrap();
        assert_eq!(pk.pubkey_hash().to_string(), "9511aa27ef39bbfa4e4f3dd15f4d66ea57f475b4");
        assert_eq!(upk.pubkey_hash().to_string(), "ac2e7daf42d2c97418fd9f78af2de552bb9c6a7a");
    }

    #[test]
    fn wpubkey_hash() {
        let pk = "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af"
            .parse::<PublicKey>()
            .unwrap();
        let upk = "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133".parse::<PublicKey>().unwrap();
        assert_eq!(
            pk.wpubkey_hash().unwrap().to_string(),
            "9511aa27ef39bbfa4e4f3dd15f4d66ea57f475b4"
        );
        assert!(upk.wpubkey_hash().is_err());
    }

    #[test]
    #[cfg(feature = "serde")]
    fn skey_serde() {
        use serde_test::{assert_tokens, Token};

        let key_wif = "3Fqd6KuqiQcNaBPV1ZNpBwVqE9ApueF4zy2YsXKtnXaGVV4R2sE3";
        let wk = key_wif.parse::<WifKey>().unwrap();

        assert_eq!(wk.network(), Network::Regtest);
        assert_tokens(&wk, &[Token::BorrowedStr(key_wif)]);
    }

    fn random_key(mut seed: u8) -> PublicKey {
        loop {
            let mut data = [0; 65];
            for byte in &mut data[..] {
                *byte = seed;
                // totally a rng
                seed = seed.wrapping_mul(41).wrapping_add(43);
            }
            if data[0] % 2 == 0 {
                data[0] = 4;
                if let Ok(key) = PublicKey::from_slice(&data[..]) {
                    return key;
                }
            } else {
                data[0] = 2 + (data[0] >> 7);
                if let Ok(key) = PublicKey::from_slice(&data[..33]) {
                    return key;
                }
            }
        }
    }

    #[test]
    fn pubkey_read_write() {
        const N_KEYS: usize = 20;
        let keys: Vec<_> = (0..N_KEYS).map(|i| random_key(i as u8)).collect();

        let mut v = vec![];
        for k in &keys {
            k.write_into(&mut v).expect("writing into vec");
        }

        let mut reader = v.as_slice();
        let mut dec_keys = vec![];
        for _ in 0..N_KEYS {
            dec_keys.push(PublicKey::read_from(&mut reader).expect("reading from vec"));
        }
        assert_eq!(keys, dec_keys);
        assert!(PublicKey::read_from(&mut reader).is_err());

        // sanity checks
        let mut empty: &[u8] = &[];
        assert!(PublicKey::read_from(&mut empty).is_err());
        assert!(PublicKey::read_from(&mut &[0; 33][..]).is_err());
        assert!(PublicKey::read_from(&mut &[2; 32][..]).is_err());
        assert!(PublicKey::read_from(&mut &[0; 65][..]).is_err());
        assert!(PublicKey::read_from(&mut &[4; 64][..]).is_err());
    }

    #[test]
    fn pubkey_to_sort_key() {
        let key1 = "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8"
            .parse::<PublicKey>()
            .unwrap();
        let key2 = PublicKey::from_secp_uncompressed(key1.to_inner());
        let arrayvec1 = ArrayVec::from_slice(
            &hex::decode_to_array::<33>(
                "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8",
            )
            .unwrap(),
        );
        let expected1 = SortKey(arrayvec1);
        let arrayvec2 = ArrayVec::from_slice(&hex::decode_to_array::<65>(
            "04ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f81794e7f3d5e420641a3bc690067df5541470c966cbca8c694bf39aa16d836918",
        ).unwrap());
        let expected2 = SortKey(arrayvec2);
        assert_eq!(key1.to_sort_key(), expected1);
        assert_eq!(key2.to_sort_key(), expected2);
    }

    #[test]
    fn pubkey_sort() {
        struct Vector {
            input: Vec<PublicKey>,
            expect: Vec<PublicKey>,
        }
        let fmt = |v: Vec<_>| {
            v.into_iter().map(|s: &str| s.parse::<PublicKey>().unwrap()).collect::<Vec<_>>()
        };
        let vectors = vec![
            // Start BIP-0067 vectors
            // Vector 1
            Vector {
                input: fmt(vec![
                    "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8",
                    "02fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f",
                ]),
                expect: fmt(vec![
                    "02fe6f0a5a297eb38c391581c4413e084773ea23954d93f7753db7dc0adc188b2f",
                    "02ff12471208c14bd580709cb2358d98975247d8765f92bc25eab3b2763ed605f8",
                ]),
            },
            // Vector 2 (Already sorted, no action required)
            Vector {
                input: fmt(vec![
                    "02632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed0",
                    "027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e77",
                    "02e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b404",
                ]),
                expect: fmt(vec![
                    "02632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed0",
                    "027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e77",
                    "02e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b404",
                ]),
            },
            // Vector 3
            Vector {
                input: fmt(vec![
                    "030000000000000000000000000000000000004141414141414141414141414141",
                    "020000000000000000000000000000000000004141414141414141414141414141",
                    "020000000000000000000000000000000000004141414141414141414141414140",
                    "030000000000000000000000000000000000004141414141414141414141414140",
                ]),
                expect: fmt(vec![
                    "020000000000000000000000000000000000004141414141414141414141414140",
                    "020000000000000000000000000000000000004141414141414141414141414141",
                    "030000000000000000000000000000000000004141414141414141414141414140",
                    "030000000000000000000000000000000000004141414141414141414141414141",
                ]),
            },
            // Vector 4: (from bitcore)
            Vector {
                input: fmt(vec![
                    "022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da",
                    "03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9",
                    "021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18",
                ]),
                expect: fmt(vec![
                    "021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18",
                    "022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da",
                    "03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9",
                ]),
            },
            // Non-BIP67 vectors
            Vector {
                input: fmt(vec![
                    "02c690d642c1310f3a1ababad94e3930e4023c930ea472e7f37f660fe485263b88",
                    "0234dd69c56c36a41230d573d68adeae0030c9bc0bf26f24d3e1b64c604d293c68",
                    "041a181bd0e79974bd7ca552e09fc42ba9c3d5dbb3753741d6f0ab3015dbfd9a22d6b001a32f5f51ac6f2c0f35e73a6a62f59e848fa854d3d21f3f231594eeaa46",
                    "032b8324c93575034047a52e9bca05a46d8347046b91a032eff07d5de8d3f2730b",
                    "04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc3816753d96001fd7cba3ce5372f5c9a0d63708183033538d07b1e532fc43aaacfa",
                    "028e1c947c8c0b8ed021088b8e981491ac7af2b8fabebea1abdb448424c8ed75b7",
                    "045d753414fa292ea5b8f56e39cfb6a0287b2546231a5cb05c4b14ab4b463d171f5128148985b23eccb1e2905374873b1f09b9487f47afa6b1f2b0083ac8b4f7e8",
                    "03004a8a3d242d7957c0b60fb7208d386fa6a0193aabd1f3f095ffd0ac097e447b",
                    "04eb0db2d71ccbb0edd8fb35092cbcae2f7fa1f06d4c170804bf52007924b569a8d2d6f6bc8fd2b3caa3253fa1bb674443743bf7fb9f94f9c0b0831a252894cfa8",
                    "04516cde23e14f2319423b7a4a7ae48b1dadceb5e9c123198d417d10895684c42eb05e210f90ccbc72448803a22312e3f122ff2939956ccef4f7316f836295ddd5",
                    "038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354",
                    "04c6bec3b07586a4b085a78cbb97e9bab6f1d3c9ebf299b65dec85213c5eacd44487de86017183120bb7ea3b6c6660c5037615fe1add2a73f800cbeeae22c60438",
                    "03e1a1cfa9eaff604ae237b7af31ffe4c01be22eb96f3da0e62c5850dd4b4386c1",
                    "028d3a2d9f1b1c5c75845944f93bc183ba23aecde53f1978b8aa1b77661be6114f",
                    "028bde91b10013e08949a318018fedbd896534a549a278e220169ee2a36517c7aa",
                    "04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc38e98ac269ffe028345c31ac8d0a365f29c8f7e7cfccac72f84e1acd02bc554f35",
                ]),
                expect: fmt(vec![
                    "0234dd69c56c36a41230d573d68adeae0030c9bc0bf26f24d3e1b64c604d293c68",
                    "028bde91b10013e08949a318018fedbd896534a549a278e220169ee2a36517c7aa",
                    "028d3a2d9f1b1c5c75845944f93bc183ba23aecde53f1978b8aa1b77661be6114f",
                    "028e1c947c8c0b8ed021088b8e981491ac7af2b8fabebea1abdb448424c8ed75b7",
                    "02c690d642c1310f3a1ababad94e3930e4023c930ea472e7f37f660fe485263b88",
                    "03004a8a3d242d7957c0b60fb7208d386fa6a0193aabd1f3f095ffd0ac097e447b",
                    "032b8324c93575034047a52e9bca05a46d8347046b91a032eff07d5de8d3f2730b",
                    "038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354",
                    "03e1a1cfa9eaff604ae237b7af31ffe4c01be22eb96f3da0e62c5850dd4b4386c1",
                    "041a181bd0e79974bd7ca552e09fc42ba9c3d5dbb3753741d6f0ab3015dbfd9a22d6b001a32f5f51ac6f2c0f35e73a6a62f59e848fa854d3d21f3f231594eeaa46",
                    "04516cde23e14f2319423b7a4a7ae48b1dadceb5e9c123198d417d10895684c42eb05e210f90ccbc72448803a22312e3f122ff2939956ccef4f7316f836295ddd5",
                    "045d753414fa292ea5b8f56e39cfb6a0287b2546231a5cb05c4b14ab4b463d171f5128148985b23eccb1e2905374873b1f09b9487f47afa6b1f2b0083ac8b4f7e8",
                    // These two pubkeys are mirrored. This helps verify the sort past the x value.
                    "04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc3816753d96001fd7cba3ce5372f5c9a0d63708183033538d07b1e532fc43aaacfa",
                    "04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc38e98ac269ffe028345c31ac8d0a365f29c8f7e7cfccac72f84e1acd02bc554f35",
                    "04c6bec3b07586a4b085a78cbb97e9bab6f1d3c9ebf299b65dec85213c5eacd44487de86017183120bb7ea3b6c6660c5037615fe1add2a73f800cbeeae22c60438",
                    "04eb0db2d71ccbb0edd8fb35092cbcae2f7fa1f06d4c170804bf52007924b569a8d2d6f6bc8fd2b3caa3253fa1bb674443743bf7fb9f94f9c0b0831a252894cfa8",
                ]),
            },
        ];
        for mut vector in vectors {
            vector.input.sort_by_cached_key(|k| PublicKey::to_sort_key(*k));
            assert_eq!(vector.input, vector.expect);
        }
    }

    #[test]
    #[cfg(all(feature = "rand", feature = "std"))]
    fn public_key_constructors() {
        let kp = Keypair::generate();

        let _ = PublicKey::from_secp(kp.clone());
        let _ = PublicKey::from_secp_uncompressed(kp);
    }

    #[test]
    fn public_key_from_str_wrong_length() {
        // Sanity checks, we accept string length 130 digits.
        let s = "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133";
        assert_eq!(s.len(), 130);
        assert!(s.parse::<PublicKey>().is_ok());
        // And 66 digits.
        let s = "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af";
        assert_eq!(s.len(), 66);
        assert!(s.parse::<PublicKey>().is_ok());

        let s = "aoeusthb";
        assert_eq!(s.len(), 8);
        let res = s.parse::<PublicKey>();
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), ParsePublicKeyError::InvalidHexLength(8));
    }

    #[test]
    fn public_key_from_str_invalid_str() {
        // Ensuring test cases fail when PublicKey::from_str is used on invalid keys
        let s = "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b142";
        assert_eq!(s.len(), 130);
        let res = s.parse::<PublicKey>();
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ParsePublicKeyError::Encoding(FromSliceError::Secp256k1(
                secp256k1::Error::InvalidPublicKey
            ))
        );

        let s = "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd169";
        assert_eq!(s.len(), 66);
        let res = s.parse::<PublicKey>();
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ParsePublicKeyError::Encoding(FromSliceError::Secp256k1(
                secp256k1::Error::InvalidPublicKey
            ))
        );

        let s = "062e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b133";
        assert_eq!(s.len(), 130);
        let res = s.parse::<PublicKey>();
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            ParsePublicKeyError::Encoding(FromSliceError::InvalidKeyPrefix(6))
        );

        let s = "042e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af191923a2964c177f5b5923ae500fca49e99492d534aa3759d6b25a8bc971b13g";
        assert_eq!(s.len(), 130);
        let res = s.parse::<PublicKey>();
        assert!(res.is_err());
        if let Err(ParsePublicKeyError::InvalidChar(err)) = res {
            assert_eq!(err.pos(), 129);
        } else {
            panic!("expected ParsePublicKeyError::InvalidChar");
        }

        let s = "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1ag";
        assert_eq!(s.len(), 66);
        let res = s.parse::<PublicKey>();
        assert!(res.is_err());
        if let Err(ParsePublicKeyError::InvalidChar(err)) = res {
            assert_eq!(err.pos(), 65);
        } else {
            panic!("expected ParsePublicKeyError::InvalidChar");
        }
    }

    #[test]
    #[allow(deprecated)] // tests the deprecated function
    #[allow(deprecated_in_future)]
    fn invalid_private_key_len() {
        use crate::Network;
        assert!(PrivateKey::from_slice(&[1u8; 31], Network::Regtest).is_err());
        assert!(PrivateKey::from_slice(&[1u8; 33], Network::Regtest).is_err());
    }

    #[test]
    fn xonly_pubkey_from_bytes() {
        let key_bytes = &hex::decode_to_array::<32>(
            "5b1e57ec453cd33fdc7cfc901450a3931fd315422558f2fb7fefb064e6e7d60d",
        )
        .expect("Failed to convert hex string to byte array");
        let xonly_pub_key = XOnlyPublicKey::from_byte_array(key_bytes)
            .expect("Failed to create an XOnlyPublicKey from a byte array");
        // Confirm that the public key from bytes serializes back to the same bytes
        assert_eq!(&xonly_pub_key.serialize().0, key_bytes);
    }

    #[test]
    fn xonly_pubkey_to_inner() {
        let key_bytes = &hex::decode_to_array::<32>(
            "5b1e57ec453cd33fdc7cfc901450a3931fd315422558f2fb7fefb064e6e7d60d",
        )
        .expect("Failed to convert hex string to byte array");
        let inner_key = secp256k1::XOnlyPublicKey::from_byte_array(*key_bytes)
            .expect("Failed to create a secp256k1 x-only public key from a byte array");
        let btc_pubkey = XOnlyPublicKey::from(inner_key);
        // Confirm that the to_inner() returns the same data that was initially wrapped
        assert_eq!(inner_key, btc_pubkey.to_inner());
    }

    #[test]
    fn keypair_from_str_roundtrip() {
        #[cfg(all(feature = "rand", feature = "std"))]
        let keypair = Keypair::generate();
        #[cfg(not(all(feature = "rand", feature = "std")))]
        let keypair = {
            let bytes = hex::decode_to_array::<32>(
                "1ede31b0e7e47c2afc65ffd158b1b1b9d3b752bba8fd117dc8b9e944a390e8d9",
            )
            .unwrap();
            let sk = PrivateKey::from_secret_bytes(bytes).unwrap();
            Keypair::from_secret_key(sk.as_inner())
        };

        // Use secp256k1::DisplaySecret, since no key type implements Display
        let encoded = format!("{}", keypair.as_inner().display_secret());
        let decoded = encoded.parse::<Keypair>().unwrap();
        assert_eq!(decoded, keypair);
    }

    #[test]
    #[cfg(all(feature = "rand", feature = "std"))]
    fn keypair_secp_roundtrip() {
        let bitcoin_key = Keypair::generate();
        let secp_key =
            secp256k1::Keypair::from_seckey_byte_array(bitcoin_key.to_secret_bytes()).unwrap();
        assert_eq!(Keypair::from_secp(secp_key), bitcoin_key);
    }

    #[test]
    #[cfg(all(feature = "rand", feature = "std"))]
    fn public_key_secp_roundtrip() {
        let bitcoin_key = Keypair::generate().to_public_key();
        let secp_key =
            secp256k1::PublicKey::from_byte_array_compressed(bitcoin_key.serialize_compressed())
                .unwrap();
        assert_eq!(PublicKey::from_secp(secp_key), bitcoin_key);
        // Also assert that generating a secp from compressed or uncompressed yields the same value
        assert_eq!(
            secp256k1::PublicKey::from_byte_array_uncompressed(
                bitcoin_key.serialize_uncompressed()
            )
            .unwrap(),
            secp_key,
        );
    }

    #[test]
    #[cfg(all(feature = "rand", feature = "std"))]
    fn xonly_secp_roundtrip() {
        let bitcoin_key = Keypair::generate().to_x_only_public_key();
        let secp_key =
            secp256k1::XOnlyPublicKey::from_byte_array(bitcoin_key.serialize().0).unwrap();
        assert_eq!(bitcoin_key, XOnlyPublicKey::from_secp(secp_key, bitcoin_key.parity()),);
    }

    #[test]
    #[cfg(all(feature = "rand", feature = "std"))]
    fn private_key_secp_roundtrip() {
        let bitcoin_key = PrivateKey::generate();
        let secp_key =
            secp256k1::SecretKey::from_secret_bytes(bitcoin_key.to_secret_bytes()).unwrap();
        assert_eq!(PrivateKey::from_secp(secp_key), bitcoin_key);
    }
}
