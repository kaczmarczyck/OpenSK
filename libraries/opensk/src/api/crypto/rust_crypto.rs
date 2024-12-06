// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This cryptography implementation is an alternative for our own library.
//!
//! You can use it with the `rust_crypto` feature. An example call to cargo test is in
//! `run_desktop_tests.sh`. It is currently impossible to use it with our version of TockOS due to
//! a compiler version imcompatibility.
//!
//! If you want to use OpenSK outside of Tock v1, maybe this is useful for you though!

use crate::api::crypto::aes256::Aes256;
use crate::api::crypto::hkdf256::Hkdf256;
use crate::api::crypto::hmac256::Hmac256;
use crate::api::crypto::sha256::Sha256;
use crate::api::crypto::{
    ecdh, ecdsa, hybrid, Crypto, AES_BLOCK_SIZE, AES_KEY_SIZE, DILITHIUM_PUB_SIZE, EC_FIELD_SIZE,
    EC_SIGNATURE_SIZE, HASH_SIZE, HMAC_KEY_SIZE, HYBRID_SIZE, TRUNCATED_HMAC_SIZE,
};
use crate::api::rng::Rng;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{
    BlockDecrypt, BlockDecryptMut, BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit,
};
use alloc::vec::Vec;
#[cfg(test)]
use core::cell::RefCell;
use core::convert::TryFrom;
use hmac::digest::FixedOutput;
use hmac::Mac;
use p256::ecdh::EphemeralSecret;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::signature::{SignatureEncoding, Signer, Verifier};
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::Digest;
#[cfg(test)]
use std::sync::{Mutex, MutexGuard};

// To be able to support hardware cryptography, we want to make sure we never compute multiple
// sha256 in parallel. Note that calling `digest` or `digest_mut` is statically correct.
// These variables track whether `new` was called but `finalize` wasn't called yet.
#[cfg(test)]
static BUSY: Mutex<()> = Mutex::new(());
#[cfg(test)]
thread_local! {
    static BUSY_GUARD: RefCell<Option<MutexGuard<'static, ()>>> = RefCell::new(None);
}

pub struct SoftwareCrypto;
pub struct SoftwareEcdh;
pub struct SoftwareEcdsa;
pub struct SoftwareHybrid;

impl Crypto for SoftwareCrypto {
    type Aes256 = SoftwareAes256;
    type Ecdh = SoftwareEcdh;
    type Ecdsa = SoftwareEcdsa;
    type Hybrid = SoftwareHybrid;
    type Sha256 = SoftwareSha256;
    type Hmac256 = SoftwareHmac256;
    type Hkdf256 = SoftwareHkdf256;
}

impl ecdh::Ecdh for SoftwareEcdh {
    type SecretKey = SoftwareEcdhSecretKey;
    type PublicKey = SoftwareEcdhPublicKey;
    type SharedSecret = SoftwareEcdhSharedSecret;
}

pub struct SoftwareEcdhSecretKey {
    ephemeral_secret: EphemeralSecret,
}

impl ecdh::SecretKey for SoftwareEcdhSecretKey {
    type PublicKey = SoftwareEcdhPublicKey;
    type SharedSecret = SoftwareEcdhSharedSecret;

    fn random(rng: &mut impl Rng) -> Self {
        let ephemeral_secret = EphemeralSecret::random(rng);
        Self { ephemeral_secret }
    }

    fn public_key(&self) -> Self::PublicKey {
        let public_key = self.ephemeral_secret.public_key();
        SoftwareEcdhPublicKey { public_key }
    }

    fn diffie_hellman(&self, public_key: &SoftwareEcdhPublicKey) -> Self::SharedSecret {
        let shared_secret = self.ephemeral_secret.diffie_hellman(&public_key.public_key);
        SoftwareEcdhSharedSecret { shared_secret }
    }
}

pub struct SoftwareEcdhPublicKey {
    public_key: p256::PublicKey,
}

impl ecdh::PublicKey for SoftwareEcdhPublicKey {
    fn from_coordinates(x: &[u8; EC_FIELD_SIZE], y: &[u8; EC_FIELD_SIZE]) -> Option<Self> {
        let encoded_point: p256::EncodedPoint =
            p256::EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
        let public_key = p256::PublicKey::from_sec1_bytes(encoded_point.as_bytes()).ok()?;
        Some(Self { public_key })
    }

    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_SIZE], y: &mut [u8; EC_FIELD_SIZE]) {
        let point = self.public_key.to_encoded_point(false);
        x.copy_from_slice(point.x().unwrap());
        y.copy_from_slice(point.y().unwrap());
    }
}

pub struct SoftwareEcdhSharedSecret {
    shared_secret: p256::ecdh::SharedSecret,
}

impl ecdh::SharedSecret for SoftwareEcdhSharedSecret {
    fn raw_secret_bytes(&self, secret: &mut [u8; EC_FIELD_SIZE]) {
        secret.copy_from_slice(self.shared_secret.raw_secret_bytes().as_slice());
    }
}

impl ecdsa::Ecdsa for SoftwareEcdsa {
    type SecretKey = SoftwareEcdsaSecretKey;
    type PublicKey = SoftwareEcdsaPublicKey;
    type Signature = SoftwareEcdsaSignature;
}

pub struct SoftwareEcdsaSecretKey {
    signing_key: SigningKey,
}

impl ecdsa::SecretKey for SoftwareEcdsaSecretKey {
    type PublicKey = SoftwareEcdsaPublicKey;
    type Signature = SoftwareEcdsaSignature;

    fn random(rng: &mut impl Rng) -> Self {
        let signing_key = SigningKey::random(rng);
        SoftwareEcdsaSecretKey { signing_key }
    }

    fn from_slice(bytes: &[u8; EC_FIELD_SIZE]) -> Option<Self> {
        let signing_key = SigningKey::from_slice(bytes).ok()?;
        Some(SoftwareEcdsaSecretKey { signing_key })
    }

    fn public_key(&self) -> Self::PublicKey {
        let verifying_key = VerifyingKey::from(&self.signing_key);
        SoftwareEcdsaPublicKey { verifying_key }
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        let signature = self.signing_key.sign(message);
        SoftwareEcdsaSignature { signature }
    }

    fn to_slice(&self, bytes: &mut [u8; EC_FIELD_SIZE]) {
        bytes.copy_from_slice(&self.signing_key.to_bytes());
    }
}

pub struct SoftwareEcdsaPublicKey {
    verifying_key: VerifyingKey,
}

impl ecdsa::PublicKey for SoftwareEcdsaPublicKey {
    type Signature = SoftwareEcdsaSignature;

    fn from_coordinates(x: &[u8; EC_FIELD_SIZE], y: &[u8; EC_FIELD_SIZE]) -> Option<Self> {
        let encoded_point: p256::EncodedPoint =
            p256::EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
        let verifying_key = VerifyingKey::from_encoded_point(&encoded_point).ok()?;
        Some(SoftwareEcdsaPublicKey { verifying_key })
    }

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
        self.verifying_key
            .verify(message, &signature.signature)
            .is_ok()
    }

    fn verify_prehash(&self, prehash: &[u8; HASH_SIZE], signature: &Self::Signature) -> bool {
        self.verifying_key
            .verify_prehash(prehash, &signature.signature)
            .is_ok()
    }

    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_SIZE], y: &mut [u8; EC_FIELD_SIZE]) {
        let point = self.verifying_key.to_encoded_point(false);
        x.copy_from_slice(point.x().unwrap());
        y.copy_from_slice(point.y().unwrap());
    }
}

pub struct SoftwareEcdsaSignature {
    signature: p256::ecdsa::Signature,
}

impl ecdsa::Signature for SoftwareEcdsaSignature {
    fn from_slice(bytes: &[u8; EC_SIGNATURE_SIZE]) -> Option<Self> {
        // Assumes EC_SIGNATURE_SIZE == 2 * EC_FIELD_SIZE
        let r = &bytes[..EC_FIELD_SIZE];
        let s = &bytes[EC_FIELD_SIZE..];
        let r = p256::NonZeroScalar::try_from(r).ok()?;
        let s = p256::NonZeroScalar::try_from(s).ok()?;
        let r = p256::FieldBytes::from(r);
        let s = p256::FieldBytes::from(s);
        let signature = p256::ecdsa::Signature::from_scalars(r, s).ok()?;
        Some(SoftwareEcdsaSignature { signature })
    }

    fn to_slice(&self, bytes: &mut [u8; EC_SIGNATURE_SIZE]) {
        bytes.copy_from_slice(&self.signature.to_bytes());
    }

    fn to_der(&self) -> Vec<u8> {
        self.signature.to_der().to_vec()
    }
}

impl hybrid::Hybrid for SoftwareHybrid {
    type SecretKey = SoftwareHybridSecretKey;
    type PublicKey = SoftwareHybridPublicKey;
    type Signature = SoftwareHybridSignature;
}

// A label generated uniformly at random from the output space of SHA256.
const LABEL: [u8; 32] = [
    43, 253, 32, 250, 19, 51, 24, 237, 138, 49, 47, 182, 4, 194, 133, 183, 177, 218, 115, 58, 92,
    117, 45, 172, 156, 5, 214, 176, 248, 103, 55, 216,
];

fn ecdsa_input(message: &[u8]) -> Vec<u8> {
    let mut input = LABEL.to_vec();
    input.extend(message);
    input
}

fn dilithium_input(message: &[u8], ecdsa_sign: &p256::ecdsa::Signature) -> Vec<u8> {
    let mut input = LABEL.to_vec();
    input.extend(message);
    input.extend(ecdsa_sign.to_der().to_vec());
    input
}

pub struct SoftwareHybridSecretKey {
    ecdsa_key: SigningKey,
    dilithium_seed: [u8; dilithium::params::SEEDBYTES],
}

impl hybrid::SecretKey for SoftwareHybridSecretKey {
    type PublicKey = SoftwareHybridPublicKey;
    type Signature = SoftwareHybridSignature;

    fn random(rng: &mut impl Rng) -> Self {
        let ecdsa_key = SigningKey::random(rng);
        let mut dilithium_seed = [0u8; dilithium::params::SEEDBYTES];
        rng.fill_bytes(&mut dilithium_seed);
        Self {
            ecdsa_key,
            dilithium_seed,
        }
    }

    fn from_slice(bytes: &[u8; HYBRID_SIZE]) -> Option<Self> {
        let ecdsa_bytes = array_ref!(bytes, 0, EC_FIELD_SIZE);
        let ecdsa_key = SigningKey::from_slice(ecdsa_bytes).ok()?;
        let dilithium_seed = *array_ref!(bytes, EC_FIELD_SIZE, dilithium::params::SEEDBYTES);

        Some(Self {
            ecdsa_key,
            dilithium_seed,
        })
    }

    fn public_key(&self) -> Self::PublicKey {
        let ecdsa_pk = VerifyingKey::from(&self.ecdsa_key);
        let (_, dilithium_pk) =
            dilithium::sign::SecKey::gensk_with_pk_from_seed(&self.dilithium_seed);
        Self::PublicKey {
            ecdsa_pk,
            dilithium_pk,
        }
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        let ecdsa_signature = self.ecdsa_key.sign(&ecdsa_input(message));
        let dilithium_sk = dilithium::sign::SecKey::gensk_from_seed(&self.dilithium_seed);
        // This wastes some stack, we could revert the Dilithium API to take a &mut [u8].
        let dilithium_signature = dilithium_sk
            .sign(&dilithium_input(message, &ecdsa_signature))
            .to_vec();
        Self::Signature {
            ecdsa_signature,
            dilithium_signature,
        }
    }

    fn to_slice(&self, bytes: &mut [u8; HYBRID_SIZE]) {
        let ecdsa_bytes = array_mut_ref!(bytes, 0, EC_FIELD_SIZE);
        ecdsa_bytes.copy_from_slice(&self.ecdsa_key.to_bytes());
        let dilithium_bytes = array_mut_ref!(bytes, EC_FIELD_SIZE, dilithium::params::SEEDBYTES);
        dilithium_bytes.copy_from_slice(&self.dilithium_seed);
    }
}

pub struct SoftwareHybridPublicKey {
    ecdsa_pk: VerifyingKey,
    dilithium_pk: dilithium::sign::PubKey,
}

impl hybrid::PublicKey for SoftwareHybridPublicKey {
    type Signature = SoftwareHybridSignature;

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
        self.ecdsa_pk
            .verify(&ecdsa_input(message), &signature.ecdsa_signature)
            .is_ok()
            && self.dilithium_pk.verify(
                &dilithium_input(message, &signature.ecdsa_signature),
                array_ref!(
                    signature.dilithium_signature,
                    0,
                    dilithium::params::SIG_SIZE_PACKED
                ),
            )
    }

    fn ecdsa_to_coordinates(&self, x: &mut [u8; EC_FIELD_SIZE], y: &mut [u8; EC_FIELD_SIZE]) {
        let point = self.ecdsa_pk.to_encoded_point(false);
        x.copy_from_slice(point.x().unwrap());
        y.copy_from_slice(point.y().unwrap());
    }

    fn dilithium_to_bytes(&self, bytes: &mut [u8; DILITHIUM_PUB_SIZE]) {
        self.dilithium_pk.to_bytes(bytes);
    }
}

pub struct SoftwareHybridSignature {
    ecdsa_signature: p256::ecdsa::Signature,
    dilithium_signature: Vec<u8>,
}

impl hybrid::Signature for SoftwareHybridSignature {
    fn into_der(self) -> Vec<u8> {
        let mut bytes = self.ecdsa_signature.to_der().to_vec();
        bytes.reserve_exact(dilithium::params::SIG_SIZE_PACKED);
        bytes.extend(self.dilithium_signature);
        bytes
    }
}

pub struct SoftwareSha256 {
    hasher: sha2::Sha256,
}

impl Sha256 for SoftwareSha256 {
    fn digest(data: &[u8]) -> [u8; HASH_SIZE] {
        sha2::Sha256::digest(data).into()
    }

    fn new() -> Self {
        #[cfg(test)]
        BUSY_GUARD.with_borrow_mut(|guard| {
            assert!(guard.is_none());
            *guard = Some(BUSY.lock().unwrap());
        });
        let hasher = sha2::Sha256::new();
        Self { hasher }
    }

    /// Digest the next part of the message to hash.
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalizes the hashing process, returns the hash value.
    fn finalize(self, output: &mut [u8; HASH_SIZE]) {
        FixedOutput::finalize_into(self.hasher, output.into());
        #[cfg(test)]
        BUSY_GUARD.with_borrow_mut(|guard| {
            assert!(guard.is_some());
            *guard = None;
        });
    }
}

pub struct SoftwareHmac256;

impl Hmac256 for SoftwareHmac256 {
    fn mac(key: &[u8; HMAC_KEY_SIZE], data: &[u8], output: &mut [u8; HASH_SIZE]) {
        let mut hmac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(key).unwrap();
        hmac.update(data);
        hmac.finalize_into(output.into());
    }

    fn verify(key: &[u8; HMAC_KEY_SIZE], data: &[u8], mac: &[u8; HASH_SIZE]) -> bool {
        let mut hmac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(key).unwrap();
        hmac.update(data);
        hmac.verify_slice(mac).is_ok()
    }

    fn verify_truncated_left(
        key: &[u8; HMAC_KEY_SIZE],
        data: &[u8],
        mac: &[u8; TRUNCATED_HMAC_SIZE],
    ) -> bool {
        let mut hmac = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(key).unwrap();
        hmac.update(data);
        hmac.verify_truncated_left(mac).is_ok()
    }
}

pub struct SoftwareHkdf256;

impl Hkdf256 for SoftwareHkdf256 {
    fn hkdf_256(ikm: &[u8], salt: &[u8; HASH_SIZE], info: &[u8], okm: &mut [u8; HASH_SIZE]) {
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm);
        hk.expand(info, okm).unwrap();
    }
}

pub struct SoftwareAes256 {
    key: [u8; AES_KEY_SIZE],
}

impl Aes256 for SoftwareAes256 {
    fn new(key: &[u8; AES_KEY_SIZE]) -> Self {
        SoftwareAes256 { key: *key }
    }

    fn encrypt_block(&self, block: &mut [u8; AES_BLOCK_SIZE]) {
        let cipher = aes::Aes256::new_from_slice(&self.key).unwrap();
        cipher.encrypt_block(block.into());
    }

    fn decrypt_block(&self, block: &mut [u8; AES_BLOCK_SIZE]) {
        let cipher = aes::Aes256::new_from_slice(&self.key).unwrap();
        cipher.decrypt_block(block.into());
    }

    fn encrypt_cbc(&self, iv: &[u8; AES_BLOCK_SIZE], plaintext: &mut [u8]) {
        let mut encryptor = cbc::Encryptor::<aes::Aes256>::new_from_slices(&self.key, iv).unwrap();
        for block in plaintext.chunks_mut(AES_BLOCK_SIZE) {
            encryptor.encrypt_block_mut(GenericArray::from_mut_slice(block));
        }
    }

    fn decrypt_cbc(&self, iv: &[u8; AES_BLOCK_SIZE], ciphertext: &mut [u8]) {
        let mut decryptor = cbc::Decryptor::<aes::Aes256>::new_from_slices(&self.key, iv).unwrap();
        for block in ciphertext.chunks_mut(AES_BLOCK_SIZE) {
            decryptor.decrypt_block_mut(GenericArray::from_mut_slice(block));
        }
    }
}
