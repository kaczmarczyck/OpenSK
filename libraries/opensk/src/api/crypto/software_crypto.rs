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

use crate::api::crypto::aes256::Aes256;
use crate::api::crypto::hkdf256::Hkdf256;
use crate::api::crypto::hmac256::Hmac256;
use crate::api::crypto::sha256::Sha256;
use crate::api::crypto::{
    ecdh, ecdsa, hybrid, Crypto, AES_BLOCK_SIZE, AES_KEY_SIZE, DILITHIUM_PUB_SIZE, EC_FIELD_SIZE,
    EC_SIGNATURE_SIZE, HASH_SIZE, HMAC_KEY_SIZE, HYBRID_SIZE, TRUNCATED_HMAC_SIZE,
};
use crate::api::rng::Rng;
use alloc::vec::Vec;
#[cfg(test)]
use core::cell::RefCell;
use crypto::Hash256;
#[cfg(test)]
use std::sync::{Mutex, MutexGuard};
use zeroize::Zeroize;

// To be able to support hardware cryptography, we want to make sure we never compute multiple
// sha256 in parallel. Note that calling `digest` or `digest_mut` is statically correct.
// These variables track whether `new` was called but `finalize` wasn't called yet.
#[cfg(test)]
static BUSY: Mutex<()> = Mutex::new(());
#[cfg(test)]
thread_local! {
    static BUSY_GUARD: RefCell<Option<MutexGuard<'static, ()>>> = RefCell::new(None);
}

/// Cryptography implementation using our own library of primitives.
///
/// Warning: The used library does not implement zeroization.
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
    sec_key: crypto::ecdh::SecKey,
}

impl ecdh::SecretKey for SoftwareEcdhSecretKey {
    type PublicKey = SoftwareEcdhPublicKey;
    type SharedSecret = SoftwareEcdhSharedSecret;

    fn random(rng: &mut impl Rng) -> Self {
        let sec_key = crypto::ecdh::SecKey::gensk(rng);
        Self { sec_key }
    }

    fn public_key(&self) -> Self::PublicKey {
        let pub_key = self.sec_key.genpk();
        SoftwareEcdhPublicKey { pub_key }
    }

    fn diffie_hellman(&self, public_key: &SoftwareEcdhPublicKey) -> Self::SharedSecret {
        let shared_secret = self.sec_key.exchange_x(&public_key.pub_key);
        SoftwareEcdhSharedSecret { shared_secret }
    }
}

pub struct SoftwareEcdhPublicKey {
    pub_key: crypto::ecdh::PubKey,
}

impl ecdh::PublicKey for SoftwareEcdhPublicKey {
    fn from_coordinates(x: &[u8; EC_FIELD_SIZE], y: &[u8; EC_FIELD_SIZE]) -> Option<Self> {
        crypto::ecdh::PubKey::from_coordinates(x, y).map(|k| Self { pub_key: k })
    }

    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_SIZE], y: &mut [u8; EC_FIELD_SIZE]) {
        self.pub_key.to_coordinates(x, y);
    }
}

#[derive(Zeroize)]
pub struct SoftwareEcdhSharedSecret {
    shared_secret: [u8; EC_FIELD_SIZE],
}

impl ecdh::SharedSecret for SoftwareEcdhSharedSecret {
    fn raw_secret_bytes(&self, secret: &mut [u8; EC_FIELD_SIZE]) {
        secret.copy_from_slice(&self.shared_secret);
    }
}

impl ecdsa::Ecdsa for SoftwareEcdsa {
    type SecretKey = SoftwareEcdsaSecretKey;
    type PublicKey = SoftwareEcdsaPublicKey;
    type Signature = SoftwareEcdsaSignature;
}

pub struct SoftwareEcdsaSecretKey {
    sec_key: crypto::ecdsa::SecKey,
}

impl ecdsa::SecretKey for SoftwareEcdsaSecretKey {
    type PublicKey = SoftwareEcdsaPublicKey;
    type Signature = SoftwareEcdsaSignature;

    fn random(rng: &mut impl Rng) -> Self {
        let sec_key = crypto::ecdsa::SecKey::gensk(rng);
        Self { sec_key }
    }

    fn from_slice(bytes: &[u8; EC_FIELD_SIZE]) -> Option<Self> {
        crypto::ecdsa::SecKey::from_bytes(bytes).map(|k| Self { sec_key: k })
    }

    fn public_key(&self) -> Self::PublicKey {
        let pub_key = self.sec_key.genpk();
        SoftwareEcdsaPublicKey { pub_key }
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        let signature = self.sec_key.sign_rfc6979::<crypto::sha256::Sha256>(message);
        SoftwareEcdsaSignature { signature }
    }

    fn to_slice(&self, bytes: &mut [u8; EC_FIELD_SIZE]) {
        self.sec_key.to_bytes(bytes);
    }
}

pub struct SoftwareEcdsaPublicKey {
    pub_key: crypto::ecdsa::PubKey,
}

impl ecdsa::PublicKey for SoftwareEcdsaPublicKey {
    type Signature = SoftwareEcdsaSignature;

    fn from_coordinates(x: &[u8; EC_FIELD_SIZE], y: &[u8; EC_FIELD_SIZE]) -> Option<Self> {
        crypto::ecdsa::PubKey::from_coordinates(x, y).map(|k| Self { pub_key: k })
    }

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
        self.pub_key
            .verify_vartime::<crypto::sha256::Sha256>(message, &signature.signature)
    }

    fn verify_prehash(&self, prehash: &[u8; HASH_SIZE], signature: &Self::Signature) -> bool {
        self.pub_key
            .verify_hash_vartime(prehash, &signature.signature)
    }

    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_SIZE], y: &mut [u8; EC_FIELD_SIZE]) {
        self.pub_key.to_coordinates(x, y);
    }
}

pub struct SoftwareEcdsaSignature {
    signature: crypto::ecdsa::Signature,
}

impl ecdsa::Signature for SoftwareEcdsaSignature {
    fn from_slice(bytes: &[u8; EC_SIGNATURE_SIZE]) -> Option<Self> {
        crypto::ecdsa::Signature::from_bytes(bytes).map(|s| SoftwareEcdsaSignature { signature: s })
    }

    fn to_slice(&self, bytes: &mut [u8; EC_SIGNATURE_SIZE]) {
        self.signature.to_bytes(bytes);
    }

    fn to_der(&self) -> Vec<u8> {
        self.signature.to_asn1_der()
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

fn dilithium_input(message: &[u8], ecdsa_sign: &crypto::ecdsa::Signature) -> Vec<u8> {
    let mut input = LABEL.to_vec();
    input.extend(message);
    input.extend(ecdsa_sign.to_asn1_der());
    input
}

pub struct SoftwareHybridSecretKey {
    ecdsa_key: crypto::ecdsa::SecKey,
    dilithium_seed: [u8; dilithium::params::SEEDBYTES],
}

impl hybrid::SecretKey for SoftwareHybridSecretKey {
    type PublicKey = SoftwareHybridPublicKey;
    type Signature = SoftwareHybridSignature;

    fn random(rng: &mut impl Rng) -> Self {
        let ecdsa_key = crypto::ecdsa::SecKey::gensk(rng);
        let mut dilithium_seed = [0u8; dilithium::params::SEEDBYTES];
        rng.fill_bytes(&mut dilithium_seed);
        Self {
            ecdsa_key,
            dilithium_seed,
        }
    }

    fn from_slice(bytes: &[u8; HYBRID_SIZE]) -> Option<Self> {
        let ecdsa_bytes = array_ref!(bytes, 0, EC_FIELD_SIZE);
        let ecdsa_key = crypto::ecdsa::SecKey::from_bytes(ecdsa_bytes)?;
        let dilithium_seed = *array_ref!(bytes, EC_FIELD_SIZE, dilithium::params::SEEDBYTES);

        Some(Self {
            ecdsa_key,
            dilithium_seed,
        })
    }

    fn public_key(&self) -> Self::PublicKey {
        let ecdsa_pk = self.ecdsa_key.genpk();
        let (_, dilithium_pk) =
            dilithium::sign::SecKey::gensk_with_pk_from_seed(&self.dilithium_seed);
        Self::PublicKey {
            ecdsa_pk,
            dilithium_pk,
        }
    }

    fn sign(&self, message: &[u8]) -> Self::Signature {
        let ecdsa_signature = self
            .ecdsa_key
            .sign_rfc6979::<crypto::sha256::Sha256>(&ecdsa_input(message));
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
        self.ecdsa_key.to_bytes(ecdsa_bytes);
        let dilithium_bytes = array_mut_ref!(bytes, EC_FIELD_SIZE, dilithium::params::SEEDBYTES);
        dilithium_bytes.copy_from_slice(&self.dilithium_seed);
    }
}

pub struct SoftwareHybridPublicKey {
    ecdsa_pk: crypto::ecdsa::PubKey,
    dilithium_pk: dilithium::sign::PubKey,
}

impl hybrid::PublicKey for SoftwareHybridPublicKey {
    type Signature = SoftwareHybridSignature;

    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool {
        self.ecdsa_pk.verify_vartime::<crypto::sha256::Sha256>(
            &ecdsa_input(message),
            &signature.ecdsa_signature,
        ) && self.dilithium_pk.verify(
            &dilithium_input(message, &signature.ecdsa_signature),
            array_ref!(
                signature.dilithium_signature,
                0,
                dilithium::params::SIG_SIZE_PACKED
            ),
        )
    }

    fn ecdsa_to_coordinates(&self, x: &mut [u8; EC_FIELD_SIZE], y: &mut [u8; EC_FIELD_SIZE]) {
        self.ecdsa_pk.to_coordinates(x, y);
    }

    fn dilithium_to_bytes(&self, bytes: &mut [u8; DILITHIUM_PUB_SIZE]) {
        self.dilithium_pk.to_bytes(bytes);
    }
}

pub struct SoftwareHybridSignature {
    ecdsa_signature: crypto::ecdsa::Signature,
    dilithium_signature: Vec<u8>,
}

impl hybrid::Signature for SoftwareHybridSignature {
    fn into_der(self) -> Vec<u8> {
        let mut bytes = self.ecdsa_signature.to_asn1_der();
        bytes.reserve_exact(dilithium::params::SIG_SIZE_PACKED);
        bytes.extend(self.dilithium_signature);
        bytes
    }
}

pub struct SoftwareSha256 {
    hasher: crypto::sha256::Sha256,
}

impl Sha256 for SoftwareSha256 {
    fn new() -> Self {
        #[cfg(test)]
        BUSY_GUARD.with_borrow_mut(|guard| {
            assert!(guard.is_none());
            *guard = Some(BUSY.lock().unwrap());
        });
        let hasher = crypto::sha256::Sha256::new();
        Self { hasher }
    }

    /// Digest the next part of the message to hash.
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalizes the hashing process, returns the hash value.
    fn finalize(self, output: &mut [u8; HASH_SIZE]) {
        self.hasher.finalize(output);
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
        crypto::hmac::hmac_256::<crypto::sha256::Sha256>(key, data, output)
    }

    fn verify(key: &[u8; HMAC_KEY_SIZE], data: &[u8], mac: &[u8; HASH_SIZE]) -> bool {
        crypto::hmac::verify_hmac_256::<crypto::sha256::Sha256>(key, data, mac)
    }

    fn verify_truncated_left(
        key: &[u8; HMAC_KEY_SIZE],
        data: &[u8],
        mac: &[u8; TRUNCATED_HMAC_SIZE],
    ) -> bool {
        crypto::hmac::verify_hmac_256_first_128bits::<crypto::sha256::Sha256>(key, data, mac)
    }
}

pub struct SoftwareHkdf256;

impl Hkdf256 for SoftwareHkdf256 {
    fn hkdf_256(ikm: &[u8], salt: &[u8; HASH_SIZE], info: &[u8], okm: &mut [u8; HASH_SIZE]) {
        crypto::hkdf::hkdf_256::<crypto::sha256::Sha256>(ikm, salt, info, okm);
    }
}

pub struct SoftwareAes256 {
    enc_key: crypto::aes256::EncryptionKey,
}

impl Aes256 for SoftwareAes256 {
    fn new(key: &[u8; AES_KEY_SIZE]) -> Self {
        let enc_key = crypto::aes256::EncryptionKey::new(key);
        SoftwareAes256 { enc_key }
    }

    fn encrypt_block(&self, block: &mut [u8; AES_BLOCK_SIZE]) {
        self.enc_key.encrypt_block(block);
    }

    fn decrypt_block(&self, block: &mut [u8; AES_BLOCK_SIZE]) {
        let dec_key = crypto::aes256::DecryptionKey::new(&self.enc_key);
        dec_key.decrypt_block(block);
    }

    fn encrypt_cbc(&self, iv: &[u8; AES_BLOCK_SIZE], plaintext: &mut [u8]) {
        crypto::cbc::cbc_encrypt(&self.enc_key, *iv, plaintext);
    }

    fn decrypt_cbc(&self, iv: &[u8; AES_BLOCK_SIZE], ciphertext: &mut [u8]) {
        let dec_key = crypto::aes256::DecryptionKey::new(&self.enc_key);
        crypto::cbc::cbc_decrypt(&dec_key, *iv, ciphertext);
    }
}
