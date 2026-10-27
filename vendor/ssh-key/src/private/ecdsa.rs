//! Elliptic Curve Digital Signature Algorithm (ECDSA) private keys.

use crate::{Algorithm, EcdsaCurve, Error, Result, public::EcdsaPublicKey};
use core::fmt;
use ctutils::{Choice, CtEq};
use encoding::{CheckedSum, Decode, Encode, Reader, Writer};
use sec1::consts::{U32, U48, U66};
use zeroize::Zeroize;

#[cfg(feature = "rand_core")]
use rand_core::CryptoRng;

#[cfg(all(
    feature = "rand_core",
    any(feature = "p256", feature = "p384", feature = "p521")
))]
use cipher::cipher::common::Generate;

/// Elliptic Curve Digital Signature Algorithm (ECDSA) private key.
#[derive(Clone)]
pub struct EcdsaPrivateKey<const SIZE: usize> {
    /// Byte array containing serialized big endian private scalar.
    bytes: [u8; SIZE],
}

impl<const SIZE: usize> EcdsaPrivateKey<SIZE> {
    /// Borrow the inner byte array as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// Convert to the inner byte array.
    #[must_use]
    pub fn into_bytes(self) -> [u8; SIZE] {
        self.bytes
    }

    /// Canonical big endian bytes without leading zero padding.
    fn significant_bytes(&self) -> &[u8] {
        let start = self
            .bytes
            .iter()
            .position(|&byte| byte != 0)
            .unwrap_or(SIZE);

        &self.bytes[start..]
    }

    /// Does this private key need to be prefixed with a leading zero?
    fn needs_leading_zero(&self) -> bool {
        self.significant_bytes()
            .first()
            .is_some_and(|&byte| byte >= 0x80)
    }
}

impl<const SIZE: usize> Decode for EcdsaPrivateKey<SIZE> {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        reader.read_prefixed(|reader| {
            // OpenSSH accepts (and normalizes) redundant leading zero bytes in
            // a positive mpint. Skip them without allocating.
            let mut saw_leading_zero = false;
            let first = loop {
                if reader.remaining_len() == 0 {
                    // Zero (or an empty payload) is not a valid private scalar.
                    return Err(Error::FormatEncoding);
                }

                let mut byte = [0u8; 1];
                reader.read(&mut byte)?;

                if byte[0] == 0 {
                    saw_leading_zero = true;
                } else {
                    break byte[0];
                }
            };

            let remaining = reader.remaining_len();
            let significant_len = remaining.checked_add(1).ok_or(encoding::Error::Length)?;

            if significant_len > SIZE {
                return Err(encoding::Error::Length.into());
            }

            // If there was no leading zero, the mpint sign bit is the MSB of
            // the first byte. A leading zero makes the value positive even if
            // that first significant byte has its MSB set.
            if !saw_leading_zero && first >= 0x80 {
                return Err(Error::FormatEncoding);
            }

            let mut bytes = [0u8; SIZE];
            let start = SIZE
                .checked_sub(significant_len)
                .ok_or(encoding::Error::Length)?;
            bytes[start] = first;

            let payload_start = start.checked_add(1).ok_or(encoding::Error::Length)?;
            reader.read(&mut bytes[payload_start..])?;

            // Reject zero and scalars outside the curve order. This is the
            // validity check which replaces the old hard-coded 32-byte minimum
            // length: short canonical scalars are legal.
            if !scalar_is_valid(&bytes) {
                return Err(Error::FormatEncoding);
            }

            Ok(Self { bytes })
        })
    }
}

/// Is this big endian scalar in the range `1..curve_order`?
fn scalar_is_valid<const SIZE: usize>(bytes: &[u8; SIZE]) -> bool {
    if bytes.iter().all(|&byte| byte == 0) {
        return false;
    }

    match curve_order(SIZE) {
        Some(order) => bytes.as_slice() < order,
        // Unknown field widths have no corresponding curve order to check.
        None => true,
    }
}

/// Get the order of the curve whose private scalar is `size` bytes.
fn curve_order(size: usize) -> Option<&'static [u8]> {
    if size == 32 {
        Some(&P256_ORDER)
    } else if size == 48 {
        Some(&P384_ORDER)
    } else if size == 66 {
        Some(&P521_ORDER)
    } else {
        None
    }
}

/// Order of the NIST P-256 curve.
const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// Order of the NIST P-384 curve.
const P384_ORDER: [u8; 48] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc7, 0x63, 0x4d, 0x81, 0xf4, 0x37, 0x2d, 0xdf,
    0x58, 0x1a, 0x0d, 0xb2, 0x48, 0xb0, 0xa7, 0x7a, 0xec, 0xec, 0x19, 0x6a, 0xcc, 0xc5, 0x29, 0x73,
];

/// Order of the NIST P-521 curve.
const P521_ORDER: [u8; 66] = [
    0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xfa, 0x51, 0x86, 0x87, 0x83, 0xbf, 0x2f, 0x96, 0x6b, 0x7f, 0xcc, 0x01, 0x48, 0xf7, 0x09,
    0xa5, 0xd0, 0x3b, 0xb5, 0xc9, 0xb8, 0x89, 0x9c, 0x47, 0xae, 0xbb, 0x6f, 0xb7, 0x1e, 0x91, 0x38,
    0x64, 0x09,
];

impl<const SIZE: usize> Encode for EcdsaPrivateKey<SIZE> {
    fn encoded_len(&self) -> encoding::Result<usize> {
        [
            4,
            self.needs_leading_zero().into(),
            self.significant_bytes().len(),
        ]
        .checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> encoding::Result<()> {
        let significant_bytes = self.significant_bytes();
        let needs_leading_zero = self.needs_leading_zero();

        [needs_leading_zero.into(), significant_bytes.len()]
            .checked_sum()?
            .encode(writer)?;

        if needs_leading_zero {
            writer.write(&[0])?;
        }

        writer.write(significant_bytes)?;
        Ok(())
    }
}

impl<const SIZE: usize> From<[u8; SIZE]> for EcdsaPrivateKey<SIZE> {
    fn from(bytes: [u8; SIZE]) -> Self {
        Self { bytes }
    }
}

impl<const SIZE: usize> AsRef<[u8; SIZE]> for EcdsaPrivateKey<SIZE> {
    fn as_ref(&self) -> &[u8; SIZE] {
        &self.bytes
    }
}

impl<const SIZE: usize> CtEq for EcdsaPrivateKey<SIZE> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_ref().ct_eq(other.as_ref())
    }
}

impl<const SIZE: usize> PartialEq for EcdsaPrivateKey<SIZE> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<const SIZE: usize> Eq for EcdsaPrivateKey<SIZE> {}

impl<const SIZE: usize> fmt::Debug for EcdsaPrivateKey<SIZE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaPrivateKey").finish_non_exhaustive()
    }
}

impl<const SIZE: usize> fmt::LowerHex for EcdsaPrivateKey<SIZE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl<const SIZE: usize> fmt::UpperHex for EcdsaPrivateKey<SIZE> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.as_ref() {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

impl<const SIZE: usize> Drop for EcdsaPrivateKey<SIZE> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(feature = "p256")]
impl From<p256::SecretKey> for EcdsaPrivateKey<32> {
    fn from(sk: p256::SecretKey) -> EcdsaPrivateKey<32> {
        EcdsaPrivateKey {
            bytes: sk.to_bytes().into(),
        }
    }
}

#[cfg(feature = "p384")]
impl From<p384::SecretKey> for EcdsaPrivateKey<48> {
    fn from(sk: p384::SecretKey) -> EcdsaPrivateKey<48> {
        EcdsaPrivateKey {
            bytes: sk.to_bytes().into(),
        }
    }
}

#[cfg(feature = "p521")]
impl From<p521::SecretKey> for EcdsaPrivateKey<66> {
    fn from(sk: p521::SecretKey) -> EcdsaPrivateKey<66> {
        // TODO(tarcieri): clean this up when migrating to hybrid-array
        let mut bytes = [0u8; 66];
        bytes.copy_from_slice(&sk.to_bytes());
        EcdsaPrivateKey { bytes }
    }
}

/// Elliptic Curve Digital Signature Algorithm (ECDSA) private/public keypair.
#[derive(Clone, Debug)]
pub enum EcdsaKeypair {
    /// NIST P-256 ECDSA keypair.
    NistP256 {
        /// Public key.
        public: sec1::EncodedPoint<U32>,

        /// Private key.
        private: EcdsaPrivateKey<32>,
    },

    /// NIST P-384 ECDSA keypair.
    NistP384 {
        /// Public key.
        public: sec1::EncodedPoint<U48>,

        /// Private key.
        private: EcdsaPrivateKey<48>,
    },

    /// NIST P-521 ECDSA keypair.
    NistP521 {
        /// Public key.
        public: sec1::EncodedPoint<U66>,

        /// Private key.
        private: EcdsaPrivateKey<66>,
    },
}

impl EcdsaKeypair {
    /// Generate a random ECDSA private key.
    ///
    /// # Errors
    /// Returns [`Error::AlgorithmUnsupported`] if support has not been enabled for the given
    /// elliptic curve, e.g. the `p256`, `p384`, or `p521` crate feature has not been enabled.
    #[cfg(feature = "rand_core")]
    #[allow(unused_variables)]
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R, curve: EcdsaCurve) -> Result<Self> {
        match curve {
            #[cfg(feature = "p256")]
            EcdsaCurve::NistP256 => {
                let private = p256::SecretKey::generate_from_rng(rng);
                let public = private.public_key();
                Ok(EcdsaKeypair::NistP256 {
                    private: private.into(),
                    public: public.into(),
                })
            }
            #[cfg(feature = "p384")]
            EcdsaCurve::NistP384 => {
                let private = p384::SecretKey::generate_from_rng(rng);
                let public = private.public_key();
                Ok(EcdsaKeypair::NistP384 {
                    private: private.into(),
                    public: public.into(),
                })
            }
            #[cfg(feature = "p521")]
            EcdsaCurve::NistP521 => {
                let private = p521::SecretKey::generate_from_rng(rng);
                let public = private.public_key();
                Ok(EcdsaKeypair::NistP521 {
                    private: private.into(),
                    public: public.into(),
                })
            }
            #[cfg(not(all(feature = "p256", feature = "p384", feature = "p521")))]
            _ => Err(Error::AlgorithmUnsupported {
                algorithm: curve.into(),
            }),
        }
    }

    /// Get the [`Algorithm`] for this public key type.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        Algorithm::Ecdsa {
            curve: self.curve(),
        }
    }

    /// Get the [`EcdsaCurve`] for this key.
    #[must_use]
    pub fn curve(&self) -> EcdsaCurve {
        match self {
            Self::NistP256 { .. } => EcdsaCurve::NistP256,
            Self::NistP384 { .. } => EcdsaCurve::NistP384,
            Self::NistP521 { .. } => EcdsaCurve::NistP521,
        }
    }

    /// Get the bytes representing the public key.
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        match self {
            Self::NistP256 { public, .. } => public.as_ref(),
            Self::NistP384 { public, .. } => public.as_ref(),
            Self::NistP521 { public, .. } => public.as_ref(),
        }
    }

    /// Get the bytes representing the private key.
    #[must_use]
    pub fn private_key_bytes(&self) -> &[u8] {
        match self {
            Self::NistP256 { private, .. } => private.as_ref(),
            Self::NistP384 { private, .. } => private.as_ref(),
            Self::NistP521 { private, .. } => private.as_ref(),
        }
    }
}

impl CtEq for EcdsaKeypair {
    fn ct_eq(&self, other: &Self) -> Choice {
        let public_eq = Choice::from(u8::from(
            EcdsaPublicKey::from(self) == EcdsaPublicKey::from(other),
        ));

        let private_key_a = match self {
            Self::NistP256 { private, .. } => private.as_slice(),
            Self::NistP384 { private, .. } => private.as_slice(),
            Self::NistP521 { private, .. } => private.as_slice(),
        };

        let private_key_b = match other {
            Self::NistP256 { private, .. } => private.as_slice(),
            Self::NistP384 { private, .. } => private.as_slice(),
            Self::NistP521 { private, .. } => private.as_slice(),
        };

        public_eq & private_key_a.ct_eq(private_key_b)
    }
}

impl Eq for EcdsaKeypair {}

impl PartialEq for EcdsaKeypair {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Decode for EcdsaKeypair {
    type Error = Error;

    fn decode(reader: &mut impl Reader) -> Result<Self> {
        match EcdsaPublicKey::decode(reader)? {
            EcdsaPublicKey::NistP256(public) => {
                let private = EcdsaPrivateKey::<32>::decode(reader)?;
                Ok(Self::NistP256 { public, private })
            }
            EcdsaPublicKey::NistP384(public) => {
                let private = EcdsaPrivateKey::<48>::decode(reader)?;
                Ok(Self::NistP384 { public, private })
            }
            EcdsaPublicKey::NistP521(public) => {
                let private = EcdsaPrivateKey::<66>::decode(reader)?;
                Ok(Self::NistP521 { public, private })
            }
        }
    }
}

impl Encode for EcdsaKeypair {
    fn encoded_len(&self) -> encoding::Result<usize> {
        let public_len = EcdsaPublicKey::from(self).encoded_len()?;

        let private_len = match self {
            Self::NistP256 { private, .. } => private.encoded_len()?,
            Self::NistP384 { private, .. } => private.encoded_len()?,
            Self::NistP521 { private, .. } => private.encoded_len()?,
        };

        [public_len, private_len].checked_sum()
    }

    fn encode(&self, writer: &mut impl Writer) -> encoding::Result<()> {
        EcdsaPublicKey::from(self).encode(writer)?;

        match self {
            Self::NistP256 { private, .. } => private.encode(writer)?,
            Self::NistP384 { private, .. } => private.encode(writer)?,
            Self::NistP521 { private, .. } => private.encode(writer)?,
        }

        Ok(())
    }
}

impl From<EcdsaKeypair> for EcdsaPublicKey {
    fn from(keypair: EcdsaKeypair) -> EcdsaPublicKey {
        EcdsaPublicKey::from(&keypair)
    }
}

impl From<&EcdsaKeypair> for EcdsaPublicKey {
    fn from(keypair: &EcdsaKeypair) -> EcdsaPublicKey {
        match keypair {
            EcdsaKeypair::NistP256 { public, .. } => EcdsaPublicKey::NistP256(*public),
            EcdsaKeypair::NistP384 { public, .. } => EcdsaPublicKey::NistP384(*public),
            EcdsaKeypair::NistP521 { public, .. } => EcdsaPublicKey::NistP521(*public),
        }
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::{EcdsaPrivateKey, P256_ORDER, P384_ORDER, P521_ORDER};
    use crate::{EcdsaCurve, LineEnding, PrivateKey};
    use alloc::vec::Vec;
    use encoding::{Decode, Encode};

    /// Deterministic test vector for P-256 with `d = 2^240 + 1`, whose
    /// canonical positive `mpint` encoding is 31 bytes. This is not a secret.
    const P256_SHORT_SCALAR_KEY: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS1zaGEy
LW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTaxK7nSyF5qW3DQnSElitXcNMCjS8xW5Dm6JaTJ+Sy
EmwsW1KnBjRd2tQEHTw4OBZYwpGI+L0rrms1i0YgzFXeAAAAmD1HZ2s9R2drAAAAE2VjZHNhLXNo
YTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNrErudLIXmpbcNCdISWK1dw0wKNLzFbkObolpMn
5LISbCxbUqcGNF3a1AQdPDg4FljCkYj4vSuuazWLRiDMVd4AAAAfAQAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAQAAAAAB
-----END OPENSSH PRIVATE KEY-----
"#;

    fn decode_raw<const SIZE: usize>(scalar: &[u8]) -> crate::Result<EcdsaPrivateKey<SIZE>> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&u32::try_from(scalar.len()).unwrap().to_be_bytes());
        encoded.extend_from_slice(scalar);

        let mut reader: &[u8] = &encoded;
        EcdsaPrivateKey::<SIZE>::decode(&mut reader)
    }

    #[test]
    fn decode_short_p256_scalar() {
        let mut scalar = [0u8; 31];
        scalar[0] = 0x01;
        scalar[30] = 0x01;

        let key = decode_raw::<32>(&scalar).unwrap();
        let mut expected = [0u8; 32];
        expected[1] = 0x01;
        expected[31] = 0x01;
        assert_eq!(key.as_slice(), &expected);

        // Re-encoding must produce a 31-byte canonical mpint again.
        let mut encoded = Vec::new();
        key.encode(&mut encoded).unwrap();
        assert_eq!(&encoded[..4], &31u32.to_be_bytes());

        let key2 = decode_raw::<32>(&encoded[4..]).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn decode_short_p384_and_p521_scalars() {
        let mut scalar = [0u8; 47];
        scalar[0] = 0x01;
        scalar[46] = 0x01;
        let key = decode_raw::<48>(&scalar).unwrap();
        let mut expected = [0u8; 48];
        expected[1] = 0x01;
        expected[47] = 0x01;
        assert_eq!(key.as_slice(), &expected);

        let mut scalar = [0u8; 65];
        scalar[0] = 0x01;
        scalar[64] = 0x01;
        let key = decode_raw::<66>(&scalar).unwrap();
        let mut expected = [0u8; 66];
        expected[1] = 0x01;
        expected[65] = 0x01;
        assert_eq!(key.as_slice(), &expected);
    }

    #[test]
    fn decode_accepts_redundant_leading_zeros() {
        // 33-byte encoding: `00 01 00...` (value 2^248). OpenSSH accepts and
        // normalizes the unnecessary leading zero.
        let mut padded = [0u8; 33];
        padded[1] = 0x01;
        let key = decode_raw::<32>(&padded).unwrap();
        let mut expected = [0u8; 32];
        expected[0] = 0x01;
        assert_eq!(key.as_slice(), &expected);

        let mut reencoded = Vec::new();
        key.encode(&mut reencoded).unwrap();
        assert_eq!(&reencoded[..4], &32u32.to_be_bytes());
        assert_eq!(&reencoded[4..], &expected);

        // Multiple redundant zero bytes are also accepted.
        let mut extra = [0u8; 34];
        extra[2] = 0x01;
        assert_eq!(decode_raw::<32>(&extra).unwrap().as_slice(), &expected);

        // A sign zero is accepted both at fixed width and with extra zeros.
        let mut sign_zero = [0u8; 32];
        sign_zero[1] = 0x80;
        let key = decode_raw::<32>(&sign_zero).unwrap();
        let mut expected_sign_zero = [0u8; 32];
        expected_sign_zero[1] = 0x80;
        assert_eq!(key.as_slice(), &expected_sign_zero);

        let mut sign_zero_with_extra = [0u8; 34];
        sign_zero_with_extra[2] = 0x80;
        let mut expected_sign_zero_with_extra = [0u8; 32];
        expected_sign_zero_with_extra[0] = 0x80;
        assert_eq!(
            decode_raw::<32>(&sign_zero_with_extra).unwrap().as_slice(),
            &expected_sign_zero_with_extra
        );
    }

    #[test]
    fn decode_rejects_zero_negative_and_out_of_range_scalars() {
        // Zero, encoded as an empty mpint, one zero byte, or a full width of
        // zero bytes.
        assert!(decode_raw::<32>(&[]).is_err());
        assert!(decode_raw::<32>(&[0x00]).is_err());
        assert!(decode_raw::<32>(&[0u8; 32]).is_err());

        // Negative mpints are rejected.
        let mut negative = [0u8; 31];
        negative[0] = 0x80;
        assert!(decode_raw::<32>(&negative).is_err());
        assert!(decode_raw::<32>(&[0xff; 32]).is_err());

        // The curve order itself and values above it are not valid scalars.
        // P-256's order has its MSB set, so its positive encoding needs a
        // leading zero byte.
        assert!(decode_raw::<32>(&P256_ORDER).is_err());
        let mut p256_order = Vec::from([0u8]);
        p256_order.extend_from_slice(&P256_ORDER);
        assert!(decode_raw::<32>(&p256_order).is_err());

        let mut p384_order = Vec::from([0u8]);
        p384_order.extend_from_slice(&P384_ORDER);
        assert!(decode_raw::<48>(&p384_order).is_err());

        assert!(decode_raw::<66>(&P521_ORDER).is_err());
        let mut p521_above_order = P521_ORDER;
        p521_above_order[65] += 1;
        assert!(decode_raw::<66>(&p521_above_order).is_err());

        // The largest valid P-256 scalar is accepted.
        let mut below_order = p256_order;
        *below_order.last_mut().unwrap() -= 1;
        assert!(decode_raw::<32>(&below_order).is_ok());

        // Too long even after leading zeros are stripped.
        assert!(decode_raw::<32>(&[0x01; 33]).is_err());
        let mut too_long_after_zeros = [0u8; 35];
        too_long_after_zeros[2] = 0x01;
        assert!(decode_raw::<32>(&too_long_after_zeros).is_err());
    }

    #[test]
    fn decode_openssh_p256_short_scalar_fixture() {
        let key = PrivateKey::from_openssh(P256_SHORT_SCALAR_KEY).unwrap();
        let ecdsa = key.key_data().ecdsa().unwrap();

        assert_eq!(ecdsa.curve(), EcdsaCurve::NistP256);
        let mut expected = [0u8; 32];
        expected[1] = 0x01;
        expected[31] = 0x01;
        assert_eq!(ecdsa.private_key_bytes(), &expected);

        let encoded = key.to_openssh(LineEnding::LF).unwrap();
        let decoded = PrivateKey::from_openssh(&*encoded).unwrap();
        assert_eq!(key, decoded);
    }
}
