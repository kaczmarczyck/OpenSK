// Copyright 2019 Google LLC
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

pub mod command;
#[cfg(feature = "with_ctap1")]
mod ctap1;
pub mod data_formats;
pub mod hid;
mod key_material;
pub mod response;
pub mod status_code;
mod storage;
mod timed_permission;

#[cfg(feature = "with_ctap2_1")]
use self::command::MAX_CREDENTIAL_COUNT_IN_LIST;
use self::command::{
    AuthenticatorClientPinParameters, AuthenticatorGetAssertionParameters,
    AuthenticatorMakeCredentialParameters, Command,
};
#[cfg(feature = "with_ctap2_1")]
use self::data_formats::AuthenticatorTransport;
use self::data_formats::{
    ClientPinSubCommand, CoseKey, CredentialProtectionPolicy, GetAssertionHmacSecretInput,
    PackedAttestationStatement, PublicKeyCredentialDescriptor, PublicKeyCredentialParameter,
    PublicKeyCredentialSource, PublicKeyCredentialType, PublicKeyCredentialUserEntity,
    SignatureAlgorithm,
};
use self::hid::ChannelID;
use self::key_material::{AAGUID, ATTESTATION_CERTIFICATE, ATTESTATION_PRIVATE_KEY};
use self::response::{
    AuthenticatorClientPinResponse, AuthenticatorGetAssertionResponse,
    AuthenticatorGetInfoResponse, AuthenticatorMakeCredentialResponse, ResponseData,
};
use self::status_code::Ctap2StatusCode;
use self::storage::PersistentStore;
#[cfg(feature = "with_ctap1")]
use self::timed_permission::U2fUserPresenceState;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use byteorder::{BigEndian, ByteOrder};
use core::convert::TryInto;
#[cfg(feature = "debug_ctap")]
use core::fmt::Write;
use crypto::cbc::{cbc_decrypt, cbc_encrypt};
use crypto::hmac::{hmac_256, verify_hmac_256, verify_hmac_256_first_128bits};
use crypto::rng256::Rng256;
use crypto::sha256::Sha256;
use crypto::Hash256;
#[cfg(feature = "debug_ctap")]
use libtock::console::Console;
use libtock::timer::{Duration, Timestamp};
use subtle::ConstantTimeEq;

// This flag enables or disables basic attestation for FIDO2. U2F is unaffected by
// this setting. The basic attestation uses the signing key from key_material.rs
// as a batch key. Turn it on if you want attestation. In this case, be aware that
// it is your responsibility to generate your own key material and keep it secret.
const USE_BATCH_ATTESTATION: bool = false;
// The signature counter is currently implemented as a global counter, if you set
// this flag to true. The spec strongly suggests to have per-credential-counters,
// but it means you can't have an infinite amount of credentials anymore. Also,
// since this is the only piece of information that needs writing often, we might
// need a flash storage friendly way to implement this feature. The implemented
// solution is a compromise to be compatible with U2F and not wasting storage.
const USE_SIGNATURE_COUNTER: bool = true;
// Those constants have to be multiples of 16, the AES block size.
const PIN_AUTH_LENGTH: usize = 16;
const PIN_TOKEN_LENGTH: usize = 32;
const PIN_PADDED_LENGTH: usize = 64;
// Our credential ID consists of
// - 16 byte initialization vector for AES-256,
// - 32 byte ECDSA private key for the credential,
// - 32 byte relying party ID hashed with SHA256,
// - 32 byte HMAC-SHA256 over everything else.
pub const ENCRYPTED_CREDENTIAL_ID_SIZE: usize = 112;
// Set this bit when checking user presence.
const UP_FLAG: u8 = 0x01;
// Set this bit when checking user verification.
const UV_FLAG: u8 = 0x04;
// Set this bit when performing attestation.
const AT_FLAG: u8 = 0x40;
// Set this bit when an extension is used.
const ED_FLAG: u8 = 0x80;

pub const TOUCH_TIMEOUT_MS: isize = 30000;
#[cfg(feature = "with_ctap1")]
const U2F_UP_PROMPT_TIMEOUT: Duration<isize> = Duration::from_ms(10000);
const RESET_TIMEOUT_MS: isize = 10000;

pub const FIDO2_VERSION_STRING: &str = "FIDO_2_0";
#[cfg(feature = "with_ctap1")]
pub const U2F_VERSION_STRING: &str = "U2F_V2";

// We currently only support one algorithm for signatures: ES256.
// This algorithm is requested in MakeCredential and advertized in GetInfo.
pub const ES256_CRED_PARAM: PublicKeyCredentialParameter = PublicKeyCredentialParameter {
    cred_type: PublicKeyCredentialType::PublicKey,
    alg: SignatureAlgorithm::ES256,
};
// You can change this value to one of the following for more privacy.
// - Some(CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList)
// - Some(CredentialProtectionPolicy::UserVerificationRequired)
const DEFAULT_CRED_PROTECT: Option<CredentialProtectionPolicy> = None;

fn check_pin_auth(hmac_key: &[u8], hmac_contents: &[u8], pin_auth: &[u8]) -> bool {
    if pin_auth.len() != PIN_AUTH_LENGTH {
        return false;
    }
    verify_hmac_256_first_128bits::<Sha256>(
        hmac_key,
        hmac_contents,
        array_ref![pin_auth, 0, PIN_AUTH_LENGTH],
    )
}

// Decrypts the HMAC secret salt(s) that were encrypted with the shared secret.
// The credRandom is used as a secret to HMAC those salts.
// The last step is to re-encrypt the outputs.
pub fn encrypt_hmac_secret_output(
    shared_secret: &[u8; 32],
    salt_enc: &[u8],
    cred_random: &[u8],
) -> Result<Vec<u8>, Ctap2StatusCode> {
    if salt_enc.len() != 32 && salt_enc.len() != 64 {
        return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_EXTENSION);
    }
    if cred_random.len() != 32 {
        // We are strict here. We need at least 32 byte, but expect exactly 32.
        return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_EXTENSION);
    }
    let aes_enc_key = crypto::aes256::EncryptionKey::new(shared_secret);
    let aes_dec_key = crypto::aes256::DecryptionKey::new(&aes_enc_key);
    // The specification specifically asks for a zero IV.
    let iv = [0; 16];

    let mut cred_random_secret = [0; 32];
    cred_random_secret.clone_from_slice(cred_random);

    // Initialization of 4 blocks in any case makes this function more readable.
    let mut blocks = [[0u8; 16]; 4];
    let block_len = salt_enc.len() / 16;
    for i in 0..block_len {
        blocks[i].copy_from_slice(&salt_enc[16 * i..16 * (i + 1)]);
    }
    cbc_decrypt(&aes_dec_key, iv, &mut blocks[..block_len]);

    let mut decrypted_salt1 = [0; 32];
    decrypted_salt1[..16].clone_from_slice(&blocks[0]);
    let output1 = hmac_256::<Sha256>(&cred_random_secret, &decrypted_salt1[..]);
    decrypted_salt1[16..].clone_from_slice(&blocks[1]);
    for i in 0..2 {
        blocks[i].copy_from_slice(&output1[16 * i..16 * (i + 1)]);
    }

    if block_len == 4 {
        let mut decrypted_salt2 = [0; 32];
        decrypted_salt2[..16].clone_from_slice(&blocks[2]);
        decrypted_salt2[16..].clone_from_slice(&blocks[3]);
        let output2 = hmac_256::<Sha256>(&cred_random_secret, &decrypted_salt2[..]);
        for i in 0..2 {
            blocks[i + 2].copy_from_slice(&output2[16 * i..16 * (i + 1)]);
        }
    }

    cbc_encrypt(&aes_enc_key, iv, &mut blocks[..block_len]);
    let mut encrypted_output = Vec::with_capacity(salt_enc.len());
    for b in &blocks[..block_len] {
        encrypted_output.extend(b);
    }
    Ok(encrypted_output)
}

// This function is adapted from https://doc.rust-lang.org/nightly/src/core/str/mod.rs.html#2110
// (as of 2020-01-20) and truncates to "max" bytes, not breaking the encoding.
// We change the return value, since we don't need the bool.
fn truncate_to_char_boundary(s: &str, mut max: usize) -> &str {
    if max >= s.len() {
        s
    } else {
        while !s.is_char_boundary(max) {
            max -= 1;
        }
        &s[..max]
    }
}

// This struct currently holds all state, not only the persistent memory. The persistent members are
// in the persistent store field.
pub struct CtapState<'a, R: Rng256, CheckUserPresence: Fn(ChannelID) -> Result<(), Ctap2StatusCode>>
{
    rng: &'a mut R,
    // A function to check user presence, ultimately returning true if user presence was detected,
    // false otherwise.
    check_user_presence: CheckUserPresence,
    persistent_store: PersistentStore,
    key_agreement_key: crypto::ecdh::SecKey,
    pin_uv_auth_token: [u8; PIN_TOKEN_LENGTH],
    consecutive_pin_mismatches: u64,
    // This variable will be irreversibly set to false RESET_TIMEOUT_MS milliseconds after boot.
    accepts_reset: bool,
    #[cfg(feature = "with_ctap1")]
    pub u2f_up_state: U2fUserPresenceState,
}

impl<'a, R, CheckUserPresence> CtapState<'a, R, CheckUserPresence>
where
    R: Rng256,
    CheckUserPresence: Fn(ChannelID) -> Result<(), Ctap2StatusCode>,
{
    pub const PIN_PROTOCOL_VERSION: u64 = 1;

    pub fn new(
        rng: &'a mut R,
        check_user_presence: CheckUserPresence,
    ) -> CtapState<'a, R, CheckUserPresence> {
        let key_agreement_key = crypto::ecdh::SecKey::gensk(rng);
        let pin_uv_auth_token = rng.gen_uniform_u8x32();
        let persistent_store = PersistentStore::new(rng);
        CtapState {
            rng,
            check_user_presence,
            persistent_store,
            key_agreement_key,
            pin_uv_auth_token,
            consecutive_pin_mismatches: 0,
            accepts_reset: true,
            #[cfg(feature = "with_ctap1")]
            u2f_up_state: U2fUserPresenceState::new(
                U2F_UP_PROMPT_TIMEOUT,
                Duration::from_ms(TOUCH_TIMEOUT_MS),
            ),
        }
    }

    pub fn check_disable_reset(&mut self, timestamp: Timestamp<isize>) {
        if timestamp - Timestamp::<isize>::from_ms(0) > Duration::from_ms(RESET_TIMEOUT_MS) {
            self.accepts_reset = false;
        }
    }

    pub fn increment_global_signature_counter(&mut self) {
        if USE_SIGNATURE_COUNTER {
            self.persistent_store.incr_global_signature_counter();
        }
    }

    // Encrypts the private key and relying party ID hash into a credential ID. Other
    // information, such as a user name, are not stored, because encrypted credential IDs
    // are used for credentials stored server-side. Also, we want the key handle to be
    // compatible with U2F.
    pub fn encrypt_key_handle(
        &mut self,
        private_key: crypto::ecdsa::SecKey,
        application: &[u8; 32],
    ) -> Vec<u8> {
        let master_keys = self.persistent_store.master_keys();
        let aes_enc_key = crypto::aes256::EncryptionKey::new(master_keys.encryption);
        let mut sk_bytes = [0; 32];
        private_key.to_bytes(&mut sk_bytes);
        let mut iv = [0; 16];
        iv.copy_from_slice(&self.rng.gen_uniform_u8x32()[..16]);

        let mut blocks = [[0u8; 16]; 4];
        blocks[0].copy_from_slice(&sk_bytes[..16]);
        blocks[1].copy_from_slice(&sk_bytes[16..]);
        blocks[2].copy_from_slice(&application[..16]);
        blocks[3].copy_from_slice(&application[16..]);
        cbc_encrypt(&aes_enc_key, iv, &mut blocks);

        let mut encrypted_id = Vec::with_capacity(ENCRYPTED_CREDENTIAL_ID_SIZE);
        encrypted_id.extend(&iv);
        for b in &blocks {
            encrypted_id.extend(b);
        }
        let id_hmac = hmac_256::<Sha256>(master_keys.hmac, &encrypted_id[..]);
        encrypted_id.extend(&id_hmac);
        encrypted_id
    }

    // Decrypts a credential ID and writes the private key into a PublicKeyCredentialSource.
    // None is returned if the HMAC test fails or the relying party does not match the
    // decrypted relying party ID hash.
    pub fn decrypt_credential_source(
        &self,
        credential_id: Vec<u8>,
        rp_id_hash: &[u8],
    ) -> Option<PublicKeyCredentialSource> {
        if credential_id.len() != ENCRYPTED_CREDENTIAL_ID_SIZE {
            return None;
        }
        let master_keys = self.persistent_store.master_keys();
        let payload_size = ENCRYPTED_CREDENTIAL_ID_SIZE - 32;
        if !verify_hmac_256::<Sha256>(
            master_keys.hmac,
            &credential_id[..payload_size],
            array_ref![credential_id, payload_size, 32],
        ) {
            return None;
        }
        let aes_enc_key = crypto::aes256::EncryptionKey::new(master_keys.encryption);
        let aes_dec_key = crypto::aes256::DecryptionKey::new(&aes_enc_key);
        let mut iv = [0; 16];
        iv.copy_from_slice(&credential_id[..16]);
        let mut blocks = [[0u8; 16]; 4];
        for i in 0..4 {
            blocks[i].copy_from_slice(&credential_id[16 * (i + 1)..16 * (i + 2)]);
        }

        cbc_decrypt(&aes_dec_key, iv, &mut blocks);
        let mut decrypted_sk = [0; 32];
        let mut decrypted_rp_id_hash = [0; 32];
        decrypted_sk[..16].clone_from_slice(&blocks[0]);
        decrypted_sk[16..].clone_from_slice(&blocks[1]);
        decrypted_rp_id_hash[..16].clone_from_slice(&blocks[2]);
        decrypted_rp_id_hash[16..].clone_from_slice(&blocks[3]);

        if rp_id_hash != decrypted_rp_id_hash {
            return None;
        }

        let sk_option = crypto::ecdsa::SecKey::from_bytes(&decrypted_sk);
        sk_option.map(|sk| PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id,
            private_key: sk,
            rp_id: String::from(""),
            user_handle: vec![],
            other_ui: None,
            cred_random: None,
            cred_protect_policy: None,
        })
    }

    pub fn process_command(&mut self, command_cbor: &[u8], cid: ChannelID) -> Vec<u8> {
        let cmd = Command::deserialize(command_cbor);
        #[cfg(feature = "debug_ctap")]
        writeln!(&mut Console::new(), "Received command: {:#?}", cmd).unwrap();
        match cmd {
            Ok(command) => {
                // Correct behavior between CTAP1 and CTAP2 isn't defined yet. Just a guess.
                #[cfg(feature = "with_ctap1")]
                {
                    self.u2f_up_state = U2fUserPresenceState::new(
                        U2F_UP_PROMPT_TIMEOUT,
                        Duration::from_ms(TOUCH_TIMEOUT_MS),
                    );
                }
                let response = match command {
                    Command::AuthenticatorMakeCredential(params) => {
                        self.process_make_credential(params, cid)
                    }
                    Command::AuthenticatorGetAssertion(params) => {
                        self.process_get_assertion(params, cid)
                    }
                    Command::AuthenticatorGetInfo => self.process_get_info(),
                    Command::AuthenticatorClientPin(params) => self.process_client_pin(params),
                    Command::AuthenticatorReset => self.process_reset(cid),
                    // TODO(kaczmarczyck) implement GetNextAssertion and FIDO 2.1 commands
                    _ => unimplemented!(),
                };
                #[cfg(feature = "debug_ctap")]
                writeln!(&mut Console::new(), "Sending response: {:#?}", response).unwrap();
                match response {
                    Ok(response_data) => {
                        let mut response_vec = vec![0x00];
                        if let Some(value) = response_data.into() {
                            if !cbor::write(value, &mut response_vec) {
                                response_vec = vec![
                                    Ctap2StatusCode::CTAP2_ERR_VENDOR_RESPONSE_CANNOT_WRITE_CBOR
                                        as u8,
                                ];
                            }
                        }
                        response_vec
                    }
                    Err(error_code) => vec![error_code as u8],
                }
            }
            Err(error_code) => vec![error_code as u8],
        }
    }

    fn process_make_credential(
        &mut self,
        make_credential_params: AuthenticatorMakeCredentialParameters,
        cid: ChannelID,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        let AuthenticatorMakeCredentialParameters {
            client_data_hash,
            rp,
            user,
            pub_key_cred_params,
            exclude_list,
            extensions,
            options,
            pin_uv_auth_param,
            pin_uv_auth_protocol,
        } = make_credential_params;

        if let Some(auth_param) = &pin_uv_auth_param {
            // This case was added in FIDO 2.1.
            if auth_param.is_empty() {
                if self.persistent_store.pin_hash().is_none() {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_NOT_SET);
                } else {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID);
                }
            }

            match pin_uv_auth_protocol {
                Some(protocol) => {
                    if protocol != CtapState::<R, CheckUserPresence>::PIN_PROTOCOL_VERSION {
                        return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
                    }
                }
                None => return Err(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER),
            }
        }

        if !pub_key_cred_params.contains(&ES256_CRED_PARAM) {
            return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM);
        }

        let (use_hmac_extension, cred_protect_policy) = if let Some(extensions) = extensions {
            let mut cred_protect = extensions.cred_protect;
            if cred_protect.unwrap_or(CredentialProtectionPolicy::UserVerificationOptional)
                < DEFAULT_CRED_PROTECT
                    .unwrap_or(CredentialProtectionPolicy::UserVerificationOptional)
            {
                cred_protect = DEFAULT_CRED_PROTECT;
            }
            (extensions.hmac_secret, cred_protect)
        } else {
            (false, None)
        };

        let cred_random = if use_hmac_extension {
            if !options.rk {
                // The extension is actually supported, but we need resident keys.
                return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_EXTENSION);
            }
            Some(self.rng.gen_uniform_u8x32().to_vec())
        } else {
            None
        };
        // TODO(kaczmarczyck) unsolicited output for default credProtect level
        let has_extension_output = use_hmac_extension || cred_protect_policy.is_some();

        let rp_id = rp.rp_id;
        if let Some(exclude_list) = exclude_list {
            for cred_desc in exclude_list {
                if self
                    .persistent_store
                    .find_credential(&rp_id, &cred_desc.key_id, pin_uv_auth_param.is_none())
                    .is_some()
                {
                    // Perform this check, so bad actors can't brute force exclude_list
                    // without user interaction.
                    (self.check_user_presence)(cid)?;
                    return Err(Ctap2StatusCode::CTAP2_ERR_CREDENTIAL_EXCLUDED);
                }
            }
        }

        // MakeCredential always requires user presence.
        // User verification depends on the PIN auth inputs, which are checked here.
        let ed_flag = if has_extension_output { ED_FLAG } else { 0 };
        let flags = match pin_uv_auth_param {
            Some(pin_auth) => {
                if self.persistent_store.pin_hash().is_none() {
                    // Specification is unclear, could be CTAP2_ERR_INVALID_OPTION.
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_NOT_SET);
                }
                if !check_pin_auth(&self.pin_uv_auth_token, &client_data_hash, &pin_auth) {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
                }
                UP_FLAG | UV_FLAG | AT_FLAG | ed_flag
            }
            None => {
                if self.persistent_store.pin_hash().is_some() {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_REQUIRED);
                }
                if options.uv {
                    return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION);
                }
                UP_FLAG | AT_FLAG | ed_flag
            }
        };

        (self.check_user_presence)(cid)?;

        let sk = crypto::ecdsa::SecKey::gensk(self.rng);
        let pk = sk.genpk();

        let rp_id_hash = Sha256::hash(rp_id.as_bytes());
        let credential_id = if options.rk {
            let random_id = self.rng.gen_uniform_u8x32().to_vec();
            let credential_source = PublicKeyCredentialSource {
                key_type: PublicKeyCredentialType::PublicKey,
                credential_id: random_id.clone(),
                private_key: sk.clone(),
                rp_id,
                user_handle: user.user_id,
                // This input is user provided, so we crop it to 64 byte for storage.
                // The UTF8 encoding is always preserved, so the string might end up shorter.
                other_ui: user
                    .user_display_name
                    .map(|s| truncate_to_char_boundary(&s, 64).to_string()),
                cred_random,
                cred_protect_policy,
            };
            self.persistent_store.store_credential(credential_source)?;
            random_id
        } else {
            self.encrypt_key_handle(sk.clone(), &rp_id_hash)
        };

        let mut auth_data = self.generate_auth_data(&rp_id_hash, flags);
        auth_data.extend(AAGUID);
        // The length is fixed to 0x20 or 0x70 and fits one byte.
        if credential_id.len() > 0xFF {
            return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_RESPONSE_TOO_LONG);
        }
        auth_data.extend(vec![0x00, credential_id.len() as u8]);
        auth_data.extend(&credential_id);
        let cose_key = match pk.to_cose_key() {
            Some(cose_key) => cose_key,
            None => return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_RESPONSE_CANNOT_WRITE_CBOR),
        };
        auth_data.extend(cose_key);
        if has_extension_output {
            let hmac_secret_output = if use_hmac_extension { Some(true) } else { None };
            let extensions_output = cbor_map_options! {
                "hmac-secret" => hmac_secret_output,
                "credProtect" => cred_protect_policy,
            };
            if !cbor::write(extensions_output, &mut auth_data) {
                return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_RESPONSE_CANNOT_WRITE_CBOR);
            }
        }

        let mut signature_data = auth_data.clone();
        signature_data.extend(client_data_hash);
        let (signature, x5c) = if USE_BATCH_ATTESTATION {
            let attestation_key =
                crypto::ecdsa::SecKey::from_bytes(ATTESTATION_PRIVATE_KEY).unwrap();
            (
                attestation_key.sign_rfc6979::<crypto::sha256::Sha256>(&signature_data),
                Some(vec![ATTESTATION_CERTIFICATE.to_vec()]),
            )
        } else {
            (
                sk.sign_rfc6979::<crypto::sha256::Sha256>(&signature_data),
                None,
            )
        };
        let attestation_statement = PackedAttestationStatement {
            alg: SignatureAlgorithm::ES256 as i64,
            sig: signature.to_asn1_der(),
            x5c,
            ecdaa_key_id: None,
        };
        Ok(ResponseData::AuthenticatorMakeCredential(
            AuthenticatorMakeCredentialResponse {
                fmt: String::from("packed"),
                auth_data,
                att_stmt: attestation_statement,
            },
        ))
    }

    fn process_get_assertion(
        &mut self,
        get_assertion_params: AuthenticatorGetAssertionParameters,
        cid: ChannelID,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        let AuthenticatorGetAssertionParameters {
            rp_id,
            client_data_hash,
            allow_list,
            extensions,
            options,
            pin_uv_auth_param,
            pin_uv_auth_protocol,
        } = get_assertion_params;

        if let Some(auth_param) = &pin_uv_auth_param {
            // This case was added in FIDO 2.1.
            if auth_param.is_empty() {
                if self.persistent_store.pin_hash().is_none() {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_NOT_SET);
                } else {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID);
                }
            }

            match pin_uv_auth_protocol {
                Some(protocol) => {
                    if protocol != CtapState::<R, CheckUserPresence>::PIN_PROTOCOL_VERSION {
                        return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
                    }
                }
                None => return Err(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER),
            }
        }

        // This case was added in FIDO 2.1.
        if pin_uv_auth_param == Some(vec![]) {
            if self.persistent_store.pin_hash().is_none() {
                return Err(Ctap2StatusCode::CTAP2_ERR_PIN_NOT_SET);
            } else {
                return Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID);
            }
        }

        if pin_uv_auth_param.is_some() {
            match pin_uv_auth_protocol {
                Some(protocol) => {
                    if protocol != CtapState::<R, CheckUserPresence>::PIN_PROTOCOL_VERSION {
                        return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
                    }
                }
                None => return Err(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER),
            }
        }

        let hmac_secret_input = extensions.map(|e| e.hmac_secret).flatten();
        if hmac_secret_input.is_some() && !options.up {
            // The extension is actually supported, but we need user presence.
            return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_EXTENSION);
        }

        // The user verification bit depends on the existance of PIN auth, since we do
        // not support internal UV. User presence is requested as an option.
        let has_uv = pin_uv_auth_param.is_some();
        let mut flags = match pin_uv_auth_param {
            Some(pin_auth) => {
                if self.persistent_store.pin_hash().is_none() {
                    // Specification is unclear, could be CTAP2_ERR_UNSUPPORTED_OPTION.
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_NOT_SET);
                }
                if !check_pin_auth(&self.pin_uv_auth_token, &client_data_hash, &pin_auth) {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
                }
                UV_FLAG
            }
            None => {
                if options.uv {
                    // The specification (inconsistently) wants CTAP2_ERR_UNSUPPORTED_OPTION.
                    return Err(Ctap2StatusCode::CTAP2_ERR_INVALID_OPTION);
                }
                0x00
            }
        };
        if options.up {
            flags |= UP_FLAG;
        }
        if hmac_secret_input.is_some() {
            flags |= ED_FLAG;
        }

        let rp_id_hash = Sha256::hash(rp_id.as_bytes());
        let mut decrypted_credential = None;
        let credentials = if let Some(allow_list) = allow_list {
            let mut found_credentials = vec![];
            for allowed_credential in allow_list {
                match self.persistent_store.find_credential(
                    &rp_id,
                    &allowed_credential.key_id,
                    !has_uv,
                ) {
                    Some(credential) => {
                        found_credentials.push(credential);
                    }
                    None => {
                        if decrypted_credential.is_none() {
                            decrypted_credential = self
                                .decrypt_credential_source(allowed_credential.key_id, &rp_id_hash);
                        }
                    }
                }
            }
            found_credentials
        } else {
            // TODO(kaczmarczyck) use GetNextAssertion
            self.persistent_store.filter_credential(&rp_id, !has_uv)
        };

        let credential = if let Some(credential) = credentials.first() {
            credential
        } else {
            decrypted_credential
                .as_ref()
                .ok_or(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS)?
        };

        if options.up {
            (self.check_user_presence)(cid)?;
        }

        self.increment_global_signature_counter();

        let mut auth_data = self.generate_auth_data(&rp_id_hash, flags);
        // Process extensions.
        if let Some(hmac_secret_input) = hmac_secret_input {
            let GetAssertionHmacSecretInput {
                key_agreement,
                salt_enc,
                salt_auth,
            } = hmac_secret_input;
            let pk: crypto::ecdh::PubKey = CoseKey::try_into(key_agreement)?;
            let shared_secret = self.key_agreement_key.exchange_x_sha256(&pk);
            // HMAC-secret does the same 16 byte truncated check.
            if !check_pin_auth(&shared_secret, &salt_enc, &salt_auth) {
                // Again, hard to tell what the correct error code here is.
                return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_EXTENSION);
            }

            let encrypted_output = match &credential.cred_random {
                Some(cr) => encrypt_hmac_secret_output(&shared_secret, &salt_enc[..], cr)?,
                // This is the case if the credential was not created with HMAC-secret.
                None => return Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_EXTENSION),
            };

            let extensions_output = cbor_map! {
                "hmac-secret" => encrypted_output,
            };
            if !cbor::write(extensions_output, &mut auth_data) {
                return Err(Ctap2StatusCode::CTAP2_ERR_VENDOR_RESPONSE_CANNOT_WRITE_CBOR);
            }
        }

        let mut signature_data = auth_data.clone();
        signature_data.extend(client_data_hash);
        let signature = credential
            .private_key
            .sign_rfc6979::<crypto::sha256::Sha256>(&signature_data);

        let cred_desc = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: credential.credential_id.clone(),
            transports: None, // You can set USB as a hint here.
        };
        let user = if flags & UV_FLAG != 0 {
            Some(PublicKeyCredentialUserEntity {
                user_id: credential.user_handle.clone(),
                user_name: None,
                user_display_name: credential.other_ui.clone(),
                user_icon: None,
            })
        } else {
            None
        };
        Ok(ResponseData::AuthenticatorGetAssertion(
            AuthenticatorGetAssertionResponse {
                credential: Some(cred_desc),
                auth_data,
                signature: signature.to_asn1_der(),
                user,
                number_of_credentials: None,
            },
        ))
    }

    fn process_get_info(&self) -> Result<ResponseData, Ctap2StatusCode> {
        let mut options_map = BTreeMap::new();
        // TODO(kaczmarczyck) add authenticatorConfig and credProtect options
        options_map.insert(String::from("rk"), true);
        options_map.insert(String::from("up"), true);
        options_map.insert(
            String::from("clientPin"),
            self.persistent_store.pin_hash().is_some(),
        );
        Ok(ResponseData::AuthenticatorGetInfo(
            AuthenticatorGetInfoResponse {
                versions: vec![
                    #[cfg(feature = "with_ctap1")]
                    String::from(U2F_VERSION_STRING),
                    String::from(FIDO2_VERSION_STRING),
                ],
                extensions: Some(vec![String::from("hmac-secret")]),
                aaguid: *AAGUID,
                options: Some(options_map),
                max_msg_size: Some(1024),
                pin_protocols: Some(vec![
                    CtapState::<R, CheckUserPresence>::PIN_PROTOCOL_VERSION,
                ]),
                #[cfg(feature = "with_ctap2_1")]
                max_credential_count_in_list: MAX_CREDENTIAL_COUNT_IN_LIST.map(|c| c as u64),
                // You can use ENCRYPTED_CREDENTIAL_ID_SIZE here, but if your
                // browser passes that value, it might be used to fingerprint.
                #[cfg(feature = "with_ctap2_1")]
                max_credential_id_length: None,
                #[cfg(feature = "with_ctap2_1")]
                transports: Some(vec![AuthenticatorTransport::Usb]),
                #[cfg(feature = "with_ctap2_1")]
                algorithms: Some(vec![ES256_CRED_PARAM]),
                default_cred_protect: DEFAULT_CRED_PROTECT,
                #[cfg(feature = "with_ctap2_1")]
                firmware_version: None,
            },
        ))
    }

    fn check_and_store_new_pin(
        &mut self,
        aes_dec_key: &crypto::aes256::DecryptionKey,
        new_pin_enc: Vec<u8>,
    ) -> bool {
        if new_pin_enc.len() != PIN_PADDED_LENGTH {
            return false;
        }
        let iv = [0; 16];
        // Assuming PIN_PADDED_LENGTH % block_size == 0 here.
        let mut blocks = [[0u8; 16]; PIN_PADDED_LENGTH / 16];
        for i in 0..PIN_PADDED_LENGTH / 16 {
            blocks[i].copy_from_slice(&new_pin_enc[i * 16..(i + 1) * 16]);
        }
        cbc_decrypt(aes_dec_key, iv, &mut blocks);
        let mut pin = vec![];
        'pin_block_loop: for block in blocks.iter().take(PIN_PADDED_LENGTH / 16) {
            for cur_char in block.iter() {
                if *cur_char != 0 {
                    pin.push(*cur_char);
                } else {
                    break 'pin_block_loop;
                }
            }
        }
        if pin.len() < 4 || pin.len() == PIN_PADDED_LENGTH {
            // TODO(kaczmarczyck) check 4 code point minimum instead
            return false;
        }
        let mut pin_hash = [0; 16];
        pin_hash.copy_from_slice(&Sha256::hash(&pin[..])[..16]);
        self.persistent_store.set_pin_hash(&pin_hash);
        true
    }

    fn check_pin_hash_enc(
        &mut self,
        aes_dec_key: &crypto::aes256::DecryptionKey,
        pin_hash_enc: Vec<u8>,
    ) -> Result<(), Ctap2StatusCode> {
        match self.persistent_store.pin_hash() {
            Some(pin_hash) => {
                if self.consecutive_pin_mismatches >= 3 {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_BLOCKED);
                }
                // We need to copy the pin hash, because decrementing the pin retries below may
                // invalidate the reference (if the page containing the pin hash is compacted).
                let pin_hash = pin_hash.to_vec();
                self.persistent_store.decr_pin_retries();
                if pin_hash_enc.len() != PIN_AUTH_LENGTH {
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID);
                }

                let iv = [0; 16];
                let mut blocks = [[0u8; 16]; 1];
                blocks[0].copy_from_slice(&pin_hash_enc[0..PIN_AUTH_LENGTH]);
                cbc_decrypt(aes_dec_key, iv, &mut blocks);

                let pin_comparison = array_ref![pin_hash, 0, PIN_AUTH_LENGTH].ct_eq(&blocks[0]);
                if !bool::from(pin_comparison) {
                    self.key_agreement_key = crypto::ecdh::SecKey::gensk(self.rng);
                    if self.persistent_store.pin_retries() == 0 {
                        return Err(Ctap2StatusCode::CTAP2_ERR_PIN_BLOCKED);
                    }
                    self.consecutive_pin_mismatches += 1;
                    if self.consecutive_pin_mismatches >= 3 {
                        return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_BLOCKED);
                    }
                    return Err(Ctap2StatusCode::CTAP2_ERR_PIN_INVALID);
                }
            }
            // This status code is not explicitly mentioned in the specification.
            None => return Err(Ctap2StatusCode::CTAP2_ERR_PIN_REQUIRED),
        }
        self.persistent_store.reset_pin_retries();
        self.consecutive_pin_mismatches = 0;
        Ok(())
    }

    fn process_get_pin_retries(&self) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        Ok(AuthenticatorClientPinResponse {
            key_agreement: None,
            pin_token: None,
            retries: Some(self.persistent_store.pin_retries() as u64),
        })
    }

    fn process_get_key_agreement(&self) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        let pk = self.key_agreement_key.genpk();
        Ok(AuthenticatorClientPinResponse {
            key_agreement: Some(CoseKey::from(pk)),
            pin_token: None,
            retries: None,
        })
    }

    fn process_set_pin(
        &mut self,
        key_agreement: CoseKey,
        pin_auth: Vec<u8>,
        new_pin_enc: Vec<u8>,
    ) -> Result<(), Ctap2StatusCode> {
        if self.persistent_store.pin_hash().is_some() {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
        }
        let pk: crypto::ecdh::PubKey = CoseKey::try_into(key_agreement)?;
        let shared_secret = self.key_agreement_key.exchange_x_sha256(&pk);

        if !check_pin_auth(&shared_secret, &new_pin_enc, &pin_auth) {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
        }

        let aes_enc_key = crypto::aes256::EncryptionKey::new(&shared_secret);
        let aes_dec_key = crypto::aes256::DecryptionKey::new(&aes_enc_key);
        if !self.check_and_store_new_pin(&aes_dec_key, new_pin_enc) {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        self.persistent_store.reset_pin_retries();
        Ok(())
    }

    fn process_change_pin(
        &mut self,
        key_agreement: CoseKey,
        pin_auth: Vec<u8>,
        new_pin_enc: Vec<u8>,
        pin_hash_enc: Vec<u8>,
    ) -> Result<(), Ctap2StatusCode> {
        if self.persistent_store.pin_retries() == 0 {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_BLOCKED);
        }
        let pk: crypto::ecdh::PubKey = CoseKey::try_into(key_agreement)?;
        let shared_secret = self.key_agreement_key.exchange_x_sha256(&pk);

        let mut auth_param_data = new_pin_enc.clone();
        auth_param_data.extend(&pin_hash_enc);
        if !check_pin_auth(&shared_secret, &auth_param_data, &pin_auth) {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
        }

        let aes_enc_key = crypto::aes256::EncryptionKey::new(&shared_secret);
        let aes_dec_key = crypto::aes256::DecryptionKey::new(&aes_enc_key);
        self.check_pin_hash_enc(&aes_dec_key, pin_hash_enc)?;

        if !self.check_and_store_new_pin(&aes_dec_key, new_pin_enc) {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        self.pin_uv_auth_token = self.rng.gen_uniform_u8x32();
        Ok(())
    }

    fn process_get_pin_token(
        &mut self,
        key_agreement: CoseKey,
        pin_hash_enc: Vec<u8>,
    ) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        if self.persistent_store.pin_retries() == 0 {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_BLOCKED);
        }
        let pk: crypto::ecdh::PubKey = CoseKey::try_into(key_agreement)?;
        let shared_secret = self.key_agreement_key.exchange_x_sha256(&pk);

        let aes_enc_key = crypto::aes256::EncryptionKey::new(&shared_secret);
        let aes_dec_key = crypto::aes256::DecryptionKey::new(&aes_enc_key);
        self.check_pin_hash_enc(&aes_dec_key, pin_hash_enc)?;

        // Assuming PIN_TOKEN_LENGTH % block_size == 0 here.
        let iv = [0; 16];
        let mut blocks = [[0u8; 16]; PIN_TOKEN_LENGTH / 16];
        for (i, item) in blocks.iter_mut().take(PIN_TOKEN_LENGTH / 16).enumerate() {
            item.copy_from_slice(&self.pin_uv_auth_token[i * 16..(i + 1) * 16]);
        }
        cbc_encrypt(&aes_enc_key, iv, &mut blocks);
        let mut pin_token = vec![];
        for item in blocks.iter().take(PIN_TOKEN_LENGTH / 16) {
            pin_token.extend(item);
        }

        Ok(AuthenticatorClientPinResponse {
            key_agreement: None,
            pin_token: Some(pin_token),
            retries: None,
        })
    }

    #[cfg(feature = "with_ctap2_1")]
    fn process_get_pin_uv_auth_token_using_uv_with_permissions(
        &self,
        _: CoseKey,
    ) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        Ok(AuthenticatorClientPinResponse {
            // User verifications is only supported through PIN currently.
            key_agreement: None,
            pin_token: Some(vec![]),
            retries: None,
        })
    }

    #[cfg(feature = "with_ctap2_1")]
    fn process_get_uv_retries(&self) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        // User verifications is only supported through PIN currently.
        Ok(AuthenticatorClientPinResponse {
            key_agreement: None,
            pin_token: None,
            retries: Some(0),
        })
    }

    #[cfg(feature = "with_ctap2_1")]
    fn process_set_min_pin_length(
        &mut self,
        _min_pin_length: u64,
        _min_pin_length_rp_ids: Vec<String>,
        _pin_auth: Vec<u8>,
    ) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        // TODO
        Ok(AuthenticatorClientPinResponse {
            key_agreement: None,
            pin_token: None,
            retries: Some(0),
        })
    }

    #[cfg(feature = "with_ctap2_1")]
    fn process_get_pin_uv_auth_token_using_pin_with_permissions(
        &mut self,
        _key_agreement: CoseKey,
        _pin_hash_enc: Vec<u8>,
        _permissions: u8,
        _permissions_rp_id: String,
    ) -> Result<AuthenticatorClientPinResponse, Ctap2StatusCode> {
        // TODO
        Ok(AuthenticatorClientPinResponse {
            key_agreement: None,
            pin_token: None,
            retries: Some(0),
        })
    }

    fn process_client_pin(
        &mut self,
        client_pin_params: AuthenticatorClientPinParameters,
    ) -> Result<ResponseData, Ctap2StatusCode> {
        let AuthenticatorClientPinParameters {
            pin_protocol,
            sub_command,
            key_agreement,
            pin_auth,
            new_pin_enc,
            pin_hash_enc,
            #[cfg(feature = "with_ctap2_1")]
            min_pin_length,
            #[cfg(feature = "with_ctap2_1")]
            min_pin_length_rp_ids,
            #[cfg(feature = "with_ctap2_1")]
            permissions,
            #[cfg(feature = "with_ctap2_1")]
            permissions_rp_id,
        } = client_pin_params;

        if pin_protocol != 1 {
            return Err(Ctap2StatusCode::CTAP2_ERR_PIN_AUTH_INVALID);
        }

        let response = match sub_command {
            ClientPinSubCommand::GetPinRetries => Some(self.process_get_pin_retries()?),
            ClientPinSubCommand::GetKeyAgreement => Some(self.process_get_key_agreement()?),
            ClientPinSubCommand::SetPin => {
                self.process_set_pin(
                    key_agreement.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    pin_auth.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    new_pin_enc.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                )?;
                None
            }
            ClientPinSubCommand::ChangePin => {
                self.process_change_pin(
                    key_agreement.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    pin_auth.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    new_pin_enc.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    pin_hash_enc.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                )?;
                None
            }
            ClientPinSubCommand::GetPinToken => Some(self.process_get_pin_token(
                key_agreement.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                pin_hash_enc.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
            )?),
            #[cfg(feature = "with_ctap2_1")]
            ClientPinSubCommand::GetPinUvAuthTokenUsingUvWithPermissions => Some(
                self.process_get_pin_uv_auth_token_using_uv_with_permissions(
                    key_agreement.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                )?,
            ),
            #[cfg(feature = "with_ctap2_1")]
            ClientPinSubCommand::GetUvRetries => Some(self.process_get_uv_retries()?),
            #[cfg(feature = "with_ctap2_1")]
            ClientPinSubCommand::SetMinPinLength => {
                self.process_set_min_pin_length(
                    min_pin_length.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    min_pin_length_rp_ids.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    pin_auth.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                )?;
                None
            }
            #[cfg(feature = "with_ctap2_1")]
            ClientPinSubCommand::GetPinUvAuthTokenUsingPinWithPermissions => {
                self.process_get_pin_uv_auth_token_using_pin_with_permissions(
                    key_agreement.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    pin_hash_enc.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    permissions.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                    permissions_rp_id.ok_or(Ctap2StatusCode::CTAP2_ERR_MISSING_PARAMETER)?,
                )?;
                None
            }
        };
        Ok(ResponseData::AuthenticatorClientPin(response))
    }

    fn process_reset(&mut self, cid: ChannelID) -> Result<ResponseData, Ctap2StatusCode> {
        // Resets are only possible in the first 10 seconds after booting.
        if !self.accepts_reset {
            return Err(Ctap2StatusCode::CTAP2_ERR_NOT_ALLOWED);
        }
        (self.check_user_presence)(cid)?;

        self.persistent_store.reset(self.rng);
        self.key_agreement_key = crypto::ecdh::SecKey::gensk(self.rng);
        self.pin_uv_auth_token = self.rng.gen_uniform_u8x32();
        self.consecutive_pin_mismatches = 0;
        #[cfg(feature = "with_ctap1")]
        {
            self.u2f_up_state = U2fUserPresenceState::new(
                U2F_UP_PROMPT_TIMEOUT,
                Duration::from_ms(TOUCH_TIMEOUT_MS),
            );
        }
        Ok(ResponseData::AuthenticatorReset)
    }

    pub fn generate_auth_data(&self, rp_id_hash: &[u8], flag_byte: u8) -> Vec<u8> {
        let mut auth_data = vec![];
        auth_data.extend(rp_id_hash);
        auth_data.push(flag_byte);
        // The global counter is only increased if USE_SIGNATURE_COUNTER is true.
        // It uses a big-endian representation.
        let mut signature_counter = [0u8; 4];
        BigEndian::write_u32(
            &mut signature_counter,
            self.persistent_store.global_signature_counter(),
        );
        auth_data.extend(&signature_counter);
        auth_data
    }
}

#[cfg(test)]
mod test {
    use super::data_formats::{
        GetAssertionExtensions, GetAssertionOptions, MakeCredentialExtensions,
        MakeCredentialOptions, PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
    };
    use super::*;
    use crypto::rng256::ThreadRng256;

    // The keep-alive logic in the processing of some commands needs a channel ID to send
    // keep-alive packets to.
    // In tests where we define a dummy user-presence check that immediately returns, the channel
    // ID is irrelevant, so we pass this (dummy but valid) value.
    const DUMMY_CHANNEL_ID: ChannelID = [0x12, 0x34, 0x56, 0x78];

    #[test]
    fn test_get_info() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present);
        let info_reponse = ctap_state.process_command(&[0x04], DUMMY_CHANNEL_ID);

        #[cfg(feature = "with_ctap2_1")]
        let mut expected_response = vec![0x00, 0xA8, 0x01];
        #[cfg(not(feature = "with_ctap2_1"))]
        let mut expected_response = vec![0x00, 0xA6, 0x01];
        // The difference here is a longer array of supported versions.
        #[cfg(not(feature = "with_ctap1"))]
        expected_response.extend(&[0x81, 0x68, 0x46, 0x49, 0x44, 0x4F, 0x5F, 0x32, 0x5F, 0x30]);
        #[cfg(feature = "with_ctap1")]
        expected_response.extend(&[
            0x82, 0x66, 0x55, 0x32, 0x46, 0x5F, 0x56, 0x32, 0x68, 0x46, 0x49, 0x44, 0x4F, 0x5F,
            0x32, 0x5F, 0x30,
        ]);
        expected_response.extend(&[
            0x02, 0x81, 0x6B, 0x68, 0x6D, 0x61, 0x63, 0x2D, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74,
            0x03, 0x50,
        ]);
        expected_response.extend(AAGUID);
        expected_response.extend(&[
            0x04, 0xA3, 0x62, 0x72, 0x6B, 0xF5, 0x62, 0x75, 0x70, 0xF5, 0x69, 0x63, 0x6C, 0x69,
            0x65, 0x6E, 0x74, 0x50, 0x69, 0x6E, 0xF4, 0x05, 0x19, 0x04, 0x00, 0x06, 0x81, 0x01,
        ]);
        #[cfg(feature = "with_ctap2_1")]
        expected_response.extend(
            [
                0x09, 0x81, 0x63, 0x75, 0x73, 0x62, 0x0A, 0x81, 0xA2, 0x63, 0x61, 0x6C, 0x67, 0x26,
                0x64, 0x74, 0x79, 0x70, 0x65, 0x6A, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, 0x2D, 0x6B,
                0x65, 0x79,
            ]
            .iter(),
        );

        assert_eq!(info_reponse, expected_response);
    }

    fn create_minimal_make_credential_parameters() -> AuthenticatorMakeCredentialParameters {
        let client_data_hash = vec![0xCD];
        let rp = PublicKeyCredentialRpEntity {
            rp_id: String::from("example.com"),
            rp_name: None,
            rp_icon: None,
        };
        let user = PublicKeyCredentialUserEntity {
            user_id: vec![0xFA, 0xB1, 0xA2],
            user_name: None,
            user_display_name: None,
            user_icon: None,
        };
        let pub_key_cred_params = vec![ES256_CRED_PARAM];
        let options = MakeCredentialOptions {
            rk: true,
            uv: false,
        };
        AuthenticatorMakeCredentialParameters {
            client_data_hash,
            rp,
            user,
            pub_key_cred_params,
            exclude_list: None,
            extensions: None,
            options,
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        }
    }

    fn create_make_credential_parameters_with_exclude_list(
        excluded_credential_id: &[u8],
    ) -> AuthenticatorMakeCredentialParameters {
        let excluded_credential_descriptor = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: excluded_credential_id.to_vec(),
            transports: None,
        };
        let exclude_list = Some(vec![excluded_credential_descriptor]);
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.exclude_list = exclude_list;
        make_credential_params
    }

    fn create_make_credential_parameters_with_cred_protect_policy(
        policy: CredentialProtectionPolicy,
    ) -> AuthenticatorMakeCredentialParameters {
        let extensions = Some(MakeCredentialExtensions {
            hmac_secret: false,
            cred_protect: Some(policy),
        });
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        make_credential_params
    }

    #[test]
    fn test_residential_process_make_credential() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present);

        let make_credential_params = create_minimal_make_credential_parameters();
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);

        match make_credential_response.unwrap() {
            ResponseData::AuthenticatorMakeCredential(make_credential_response) => {
                let AuthenticatorMakeCredentialResponse {
                    fmt,
                    auth_data,
                    att_stmt,
                } = make_credential_response;
                // The expected response is split to only assert the non-random parts.
                assert_eq!(fmt, "packed");
                let mut expected_auth_data = vec![
                    0xA3, 0x79, 0xA6, 0xF6, 0xEE, 0xAF, 0xB9, 0xA5, 0x5E, 0x37, 0x8C, 0x11, 0x80,
                    0x34, 0xE2, 0x75, 0x1E, 0x68, 0x2F, 0xAB, 0x9F, 0x2D, 0x30, 0xAB, 0x13, 0xD2,
                    0x12, 0x55, 0x86, 0xCE, 0x19, 0x47, 0x41, 0x00, 0x00, 0x00, 0x00,
                ];
                expected_auth_data.extend(AAGUID);
                expected_auth_data.extend(&[0x00, 0x20]);
                assert_eq!(
                    auth_data[0..expected_auth_data.len()],
                    expected_auth_data[..]
                );
                assert_eq!(att_stmt.alg, SignatureAlgorithm::ES256 as i64);
            }
            _ => panic!("Invalid response type"),
        }
    }

    #[test]
    fn test_non_residential_process_make_credential() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.options.rk = false;
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);

        match make_credential_response.unwrap() {
            ResponseData::AuthenticatorMakeCredential(make_credential_response) => {
                let AuthenticatorMakeCredentialResponse {
                    fmt,
                    auth_data,
                    att_stmt,
                } = make_credential_response;
                // The expected response is split to only assert the non-random parts.
                assert_eq!(fmt, "packed");
                let mut expected_auth_data = vec![
                    0xA3, 0x79, 0xA6, 0xF6, 0xEE, 0xAF, 0xB9, 0xA5, 0x5E, 0x37, 0x8C, 0x11, 0x80,
                    0x34, 0xE2, 0x75, 0x1E, 0x68, 0x2F, 0xAB, 0x9F, 0x2D, 0x30, 0xAB, 0x13, 0xD2,
                    0x12, 0x55, 0x86, 0xCE, 0x19, 0x47, 0x41, 0x00, 0x00, 0x00, 0x00,
                ];
                expected_auth_data.extend(AAGUID);
                expected_auth_data.extend(&[0x00, ENCRYPTED_CREDENTIAL_ID_SIZE as u8]);
                assert_eq!(
                    auth_data[0..expected_auth_data.len()],
                    expected_auth_data[..]
                );
                assert_eq!(att_stmt.alg, SignatureAlgorithm::ES256 as i64);
            }
            _ => panic!("Invalid response type"),
        }
    }

    #[test]
    fn test_process_make_credential_unsupported_algorithm() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present);

        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.pub_key_cred_params = vec![];
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);

        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM)
        );
    }

    #[test]
    fn test_process_make_credential_credential_excluded() {
        let mut rng = ThreadRng256 {};
        let excluded_private_key = crypto::ecdsa::SecKey::gensk(&mut rng);
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present);

        let excluded_credential_id = vec![0x01, 0x23, 0x45, 0x67];
        let make_credential_params =
            create_make_credential_parameters_with_exclude_list(&excluded_credential_id);
        let excluded_credential_source = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: excluded_credential_id,
            private_key: excluded_private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![],
            other_ui: None,
            cred_random: None,
            cred_protect_policy: None,
        };
        assert!(ctap_state
            .persistent_store
            .store_credential(excluded_credential_source)
            .is_ok());

        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_CREDENTIAL_EXCLUDED)
        );
    }

    #[test]
    fn test_process_make_credential_credential_with_cred_protect() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present);

        let test_policy = CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList;
        let make_credential_params =
            create_make_credential_parameters_with_cred_protect_policy(test_policy);
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);
        assert!(make_credential_response.is_ok());

        let stored_credential = ctap_state
            .persistent_store
            .filter_credential("example.com", false)
            .pop()
            .unwrap();
        let credential_id = stored_credential.credential_id;
        assert_eq!(stored_credential.cred_protect_policy, Some(test_policy));

        let make_credential_params =
            create_make_credential_parameters_with_exclude_list(&credential_id);
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);
        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_CREDENTIAL_EXCLUDED)
        );

        let test_policy = CredentialProtectionPolicy::UserVerificationRequired;
        let make_credential_params =
            create_make_credential_parameters_with_cred_protect_policy(test_policy);
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);
        assert!(make_credential_response.is_ok());

        let stored_credential = ctap_state
            .persistent_store
            .filter_credential("example.com", false)
            .pop()
            .unwrap();
        let credential_id = stored_credential.credential_id;
        assert_eq!(stored_credential.cred_protect_policy, Some(test_policy));

        let make_credential_params =
            create_make_credential_parameters_with_exclude_list(&credential_id);
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);
        assert!(make_credential_response.is_ok());
    }

    #[test]
    fn test_process_make_credential_hmac_secret() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present);

        let extensions = Some(MakeCredentialExtensions {
            hmac_secret: true,
            cred_protect: None,
        });
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = extensions;
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);

        match make_credential_response.unwrap() {
            ResponseData::AuthenticatorMakeCredential(make_credential_response) => {
                let AuthenticatorMakeCredentialResponse {
                    fmt,
                    auth_data,
                    att_stmt,
                } = make_credential_response;
                // The expected response is split to only assert the non-random parts.
                assert_eq!(fmt, "packed");
                let mut expected_auth_data = vec![
                    0xA3, 0x79, 0xA6, 0xF6, 0xEE, 0xAF, 0xB9, 0xA5, 0x5E, 0x37, 0x8C, 0x11, 0x80,
                    0x34, 0xE2, 0x75, 0x1E, 0x68, 0x2F, 0xAB, 0x9F, 0x2D, 0x30, 0xAB, 0x13, 0xD2,
                    0x12, 0x55, 0x86, 0xCE, 0x19, 0x47, 0xC1, 0x00, 0x00, 0x00, 0x00,
                ];
                expected_auth_data.extend(AAGUID);
                expected_auth_data.extend(&[0x00, 0x20]);
                assert_eq!(
                    auth_data[0..expected_auth_data.len()],
                    expected_auth_data[..]
                );
                let expected_extension_cbor = vec![
                    0xA1, 0x6B, 0x68, 0x6D, 0x61, 0x63, 0x2D, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74,
                    0xF5,
                ];
                assert_eq!(
                    auth_data[auth_data.len() - expected_extension_cbor.len()..auth_data.len()],
                    expected_extension_cbor[..]
                );
                assert_eq!(att_stmt.alg, SignatureAlgorithm::ES256 as i64);
            }
            _ => panic!("Invalid response type"),
        }
    }

    #[test]
    fn test_process_make_credential_cancelled() {
        let mut rng = ThreadRng256 {};
        let user_presence_always_cancel = |_| Err(Ctap2StatusCode::CTAP2_ERR_KEEPALIVE_CANCEL);
        let mut ctap_state = CtapState::new(&mut rng, user_presence_always_cancel);

        let make_credential_params = create_minimal_make_credential_parameters();
        let make_credential_response =
            ctap_state.process_make_credential(make_credential_params, DUMMY_CHANNEL_ID);

        assert_eq!(
            make_credential_response,
            Err(Ctap2StatusCode::CTAP2_ERR_KEEPALIVE_CANCEL)
        );
    }

    #[test]
    fn test_residential_process_get_assertion() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present);

        let make_credential_params = create_minimal_make_credential_parameters();
        assert!(ctap_state
            .process_make_credential(make_credential_params, DUMMY_CHANNEL_ID)
            .is_ok());

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: None,
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(get_assertion_params, DUMMY_CHANNEL_ID);

        match get_assertion_response.unwrap() {
            ResponseData::AuthenticatorGetAssertion(get_assertion_response) => {
                let AuthenticatorGetAssertionResponse {
                    auth_data,
                    user,
                    number_of_credentials,
                    ..
                } = get_assertion_response;
                let expected_auth_data = vec![
                    0xA3, 0x79, 0xA6, 0xF6, 0xEE, 0xAF, 0xB9, 0xA5, 0x5E, 0x37, 0x8C, 0x11, 0x80,
                    0x34, 0xE2, 0x75, 0x1E, 0x68, 0x2F, 0xAB, 0x9F, 0x2D, 0x30, 0xAB, 0x13, 0xD2,
                    0x12, 0x55, 0x86, 0xCE, 0x19, 0x47, 0x00, 0x00, 0x00, 0x00, 0x01,
                ];
                assert_eq!(auth_data, expected_auth_data);
                assert!(user.is_none());
                assert!(number_of_credentials.is_none());
            }
            _ => panic!("Invalid response type"),
        }
    }

    #[test]
    fn test_residential_process_get_assertion_hmac_secret() {
        let mut rng = ThreadRng256 {};
        let sk = crypto::ecdh::SecKey::gensk(&mut rng);
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present);

        let make_extensions = Some(MakeCredentialExtensions {
            hmac_secret: true,
            cred_protect: None,
        });
        let mut make_credential_params = create_minimal_make_credential_parameters();
        make_credential_params.extensions = make_extensions;
        assert!(ctap_state
            .process_make_credential(make_credential_params, DUMMY_CHANNEL_ID)
            .is_ok());

        let pk = sk.genpk();
        let hmac_secret_input = GetAssertionHmacSecretInput {
            key_agreement: CoseKey::from(pk),
            salt_enc: vec![0x02; 32],
            salt_auth: vec![0x03; 16],
        };
        let get_extensions = Some(GetAssertionExtensions {
            hmac_secret: Some(hmac_secret_input),
        });

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: get_extensions,
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(get_assertion_params, DUMMY_CHANNEL_ID);

        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_EXTENSION)
        );
    }

    #[test]
    fn test_residential_process_get_assertion_with_cred_protect() {
        let mut rng = ThreadRng256 {};
        let private_key = crypto::ecdsa::SecKey::gensk(&mut rng);
        let credential_id = rng.gen_uniform_u8x32().to_vec();
        let user_immediately_present = |_| Ok(());
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present);

        let cred_desc = PublicKeyCredentialDescriptor {
            key_type: PublicKeyCredentialType::PublicKey,
            key_id: credential_id.clone(),
            transports: None, // You can set USB as a hint here.
        };
        let credential = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id: credential_id.clone(),
            private_key: private_key.clone(),
            rp_id: String::from("example.com"),
            user_handle: vec![0x00],
            other_ui: None,
            cred_random: None,
            cred_protect_policy: Some(
                CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIdList,
            ),
        };
        assert!(ctap_state
            .persistent_store
            .store_credential(credential)
            .is_ok());

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: None,
            extensions: None,
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(get_assertion_params, DUMMY_CHANNEL_ID);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS),
        );

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: Some(vec![cred_desc.clone()]),
            extensions: None,
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(get_assertion_params, DUMMY_CHANNEL_ID);
        assert!(get_assertion_response.is_ok());

        let credential = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id,
            private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![0x00],
            other_ui: None,
            cred_random: None,
            cred_protect_policy: Some(CredentialProtectionPolicy::UserVerificationRequired),
        };
        assert!(ctap_state
            .persistent_store
            .store_credential(credential)
            .is_ok());

        let get_assertion_params = AuthenticatorGetAssertionParameters {
            rp_id: String::from("example.com"),
            client_data_hash: vec![0xCD],
            allow_list: Some(vec![cred_desc]),
            extensions: None,
            options: GetAssertionOptions {
                up: false,
                uv: false,
            },
            pin_uv_auth_param: None,
            pin_uv_auth_protocol: None,
        };
        let get_assertion_response =
            ctap_state.process_get_assertion(get_assertion_params, DUMMY_CHANNEL_ID);
        assert_eq!(
            get_assertion_response,
            Err(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS),
        );
    }

    #[test]
    fn test_process_reset() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let private_key = crypto::ecdsa::SecKey::gensk(&mut rng);
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present);

        let credential_id = vec![0x01, 0x23, 0x45, 0x67];
        let credential_source = PublicKeyCredentialSource {
            key_type: PublicKeyCredentialType::PublicKey,
            credential_id,
            private_key,
            rp_id: String::from("example.com"),
            user_handle: vec![],
            other_ui: None,
            cred_random: None,
            cred_protect_policy: None,
        };
        assert!(ctap_state
            .persistent_store
            .store_credential(credential_source)
            .is_ok());
        assert!(ctap_state.persistent_store.count_credentials() > 0);

        let reset_reponse = ctap_state.process_command(&[0x07], DUMMY_CHANNEL_ID);
        let expected_response = vec![0x00];
        assert_eq!(reset_reponse, expected_response);
        assert!(ctap_state.persistent_store.count_credentials() == 0);
    }

    #[test]
    fn test_process_reset_cancelled() {
        let mut rng = ThreadRng256 {};
        let user_presence_always_cancel = |_| Err(Ctap2StatusCode::CTAP2_ERR_KEEPALIVE_CANCEL);
        let mut ctap_state = CtapState::new(&mut rng, user_presence_always_cancel);

        let reset_reponse = ctap_state.process_reset(DUMMY_CHANNEL_ID);

        assert_eq!(
            reset_reponse,
            Err(Ctap2StatusCode::CTAP2_ERR_KEEPALIVE_CANCEL)
        );
    }

    #[test]
    fn test_encrypt_decrypt_credential() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let private_key = crypto::ecdsa::SecKey::gensk(&mut rng);
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present);

        // Usually, the relying party ID or its hash is provided by the client.
        // We are not testing the correctness of our SHA256 here, only if it is checked.
        let rp_id_hash = [0x55; 32];
        let encrypted_id = ctap_state.encrypt_key_handle(private_key.clone(), &rp_id_hash);
        let decrypted_source = ctap_state
            .decrypt_credential_source(encrypted_id, &rp_id_hash)
            .unwrap();

        assert_eq!(private_key, decrypted_source.private_key);
    }

    #[test]
    fn test_encrypt_decrypt_bad_hmac() {
        let mut rng = ThreadRng256 {};
        let user_immediately_present = |_| Ok(());
        let private_key = crypto::ecdsa::SecKey::gensk(&mut rng);
        let mut ctap_state = CtapState::new(&mut rng, user_immediately_present);

        // Same as above.
        let rp_id_hash = [0x55; 32];
        let encrypted_id = ctap_state.encrypt_key_handle(private_key, &rp_id_hash);
        for i in 0..encrypted_id.len() {
            let mut modified_id = encrypted_id.clone();
            modified_id[i] ^= 0x01;
            assert!(ctap_state
                .decrypt_credential_source(modified_id, &rp_id_hash)
                .is_none());
        }
    }

    #[test]
    fn test_encrypt_hmac_secret_output() {
        let shared_secret = [0x55; 32];
        let salt_enc = [0x5E; 32];
        let cred_random = [0xC9; 32];
        let output = encrypt_hmac_secret_output(&shared_secret, &salt_enc, &cred_random);
        assert_eq!(output.unwrap().len(), 32);

        let salt_enc = [0x5E; 48];
        let output = encrypt_hmac_secret_output(&shared_secret, &salt_enc, &cred_random);
        assert_eq!(
            output,
            Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_EXTENSION)
        );

        let salt_enc = [0x5E; 64];
        let output = encrypt_hmac_secret_output(&shared_secret, &salt_enc, &cred_random);
        assert_eq!(output.unwrap().len(), 64);

        let salt_enc = [0x5E; 32];
        let cred_random = [0xC9; 33];
        let output = encrypt_hmac_secret_output(&shared_secret, &salt_enc, &cred_random);
        assert_eq!(
            output,
            Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_EXTENSION)
        );
    }
}
