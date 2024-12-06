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

use super::{DILITHIUM_PUB_SIZE, EC_FIELD_SIZE, HYBRID_SIZE};
use crate::api::rng::Rng;
use alloc::vec::Vec;

/// Container for all Hybrid ECDSA + Dilithium cryptographic material.
pub trait Hybrid {
    type SecretKey: SecretKey<PublicKey = Self::PublicKey, Signature = Self::Signature>;
    type PublicKey: PublicKey<Signature = Self::Signature>;
    type Signature: Signature;
}

/// Hybrid ECDSA + Dilithium signing key.
pub trait SecretKey: Sized {
    type PublicKey: PublicKey;
    type Signature: Signature;

    /// Generates a new random secret key.
    fn random(rng: &mut impl Rng) -> Self;

    /// Creates a signing key from its representation in bytes.
    fn from_slice(bytes: &[u8; HYBRID_SIZE]) -> Option<Self>;

    /// Computes the corresponding public key for this private key.
    fn public_key(&self) -> Self::PublicKey;

    /// Signs the message.
    ///
    /// For hashing, SHA256 is used implicitly.
    fn sign(&self, message: &[u8]) -> Self::Signature;

    /// Writes the signing key bytes into the passed in parameter.
    fn to_slice(&self, bytes: &mut [u8; HYBRID_SIZE]);
}

/// Hybrid ECDSA + Dilithium verifying key.
pub trait PublicKey: Sized {
    type Signature: Signature;

    /// Verifies if the signature matches the message.
    ///
    /// For hashing, SHA256 is used implicitly.
    fn verify(&self, message: &[u8], signature: &Self::Signature) -> bool;

    /// Writes the ECDSA public key coordinates into the passed in parameters.
    fn ecdsa_to_coordinates(&self, x: &mut [u8; EC_FIELD_SIZE], y: &mut [u8; EC_FIELD_SIZE]);

    /// Writes the Dilithium bytes into the passed in parameters.
    fn dilithium_to_bytes(&self, bytes: &mut [u8; DILITHIUM_PUB_SIZE]);
}

/// Hybrid ECDSA + Dilithium signature.
pub trait Signature: Sized {
    /// Encodes the signatures as ASN1 DER.
    fn into_der(self) -> Vec<u8>;
}
