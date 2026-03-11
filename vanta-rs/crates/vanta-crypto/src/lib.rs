use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use vanta_wire::{AuthFinishPayload, AuthInitPayload, PeerId, SessionId};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

const LABEL_C2S_KEY: &[u8] = b"vanta/c2s/key";
const LABEL_S2C_KEY: &[u8] = b"vanta/s2c/key";
const LABEL_C2S_NONCE: &[u8] = b"vanta/c2s/nonce";
const LABEL_S2C_NONCE: &[u8] = b"vanta/s2c/nonce";
const LABEL_RESUME: &[u8] = b"vanta/resume";
const LABEL_AUDIT: &[u8] = b"vanta/audit";
const LABEL_SESSION_ID: &[u8] = b"vanta/session-id";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("invalid identity key")]
    InvalidIdentityKey,
    #[error("aead failure")]
    AeadFailure,
    #[error("hkdf expansion failure")]
    Hkdf,
    #[error("wire encoding error")]
    Wire(#[from] vanta_wire::WireError),
}

#[derive(Clone)]
pub struct IdentityKeypair {
    signing: SigningKey,
}

impl IdentityKeypair {
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&bytes),
        }
    }

    pub fn peer_id(&self) -> PeerId {
        PeerId::from(self.signing.verifying_key().to_bytes())
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.signing.to_bytes())
    }
}

#[derive(Clone)]
pub struct EphemeralKeypair {
    secret: StaticSecret,
    public: X25519PublicKey,
}

impl EphemeralKeypair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    pub fn diffie_hellman(&self, remote_public: [u8; 32]) -> [u8; 32] {
        let shared = self
            .secret
            .diffie_hellman(&X25519PublicKey::from(remote_public));
        shared.to_bytes()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Transcript {
    chunks: Vec<Vec<u8>>,
}

impl Transcript {
    pub fn push(&mut self, bytes: &[u8]) {
        self.chunks.push(bytes.to_vec());
    }

    pub fn finalize(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        for chunk in &self.chunks {
            digest.update((chunk.len() as u32).to_be_bytes());
            digest.update(chunk);
        }
        digest.finalize().into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionKeys {
    pub client_to_server_key: [u8; 32],
    pub server_to_client_key: [u8; 32],
    pub client_to_server_nonce_base: [u8; 4],
    pub server_to_client_nonce_base: [u8; 4],
    pub resume_secret: [u8; 32],
    pub audit_binding_key: [u8; 32],
    pub session_id: SessionId,
}

impl SessionKeys {
    pub fn nonce(&self, initiator_to_responder: bool, sequence: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        let base = if initiator_to_responder {
            self.client_to_server_nonce_base
        } else {
            self.server_to_client_nonce_base
        };
        nonce[..4].copy_from_slice(&base);
        nonce[4..].copy_from_slice(&sequence.to_be_bytes());
        nonce
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RolePerspective {
    Client,
    Server,
}

pub fn derive_session_keys(
    shared_secret: [u8; 32],
    transcript_hash: [u8; 32],
) -> Result<SessionKeys, CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(Some(&transcript_hash), &shared_secret);
    let mut client_to_server_key = [0; 32];
    let mut server_to_client_key = [0; 32];
    let mut client_to_server_nonce_base = [0; 4];
    let mut server_to_client_nonce_base = [0; 4];
    let mut resume_secret = [0; 32];
    let mut audit_binding_key = [0; 32];
    let mut session_id = [0; 16];

    hkdf.expand(LABEL_C2S_KEY, &mut client_to_server_key)
        .map_err(|_| CryptoError::Hkdf)?;
    hkdf.expand(LABEL_S2C_KEY, &mut server_to_client_key)
        .map_err(|_| CryptoError::Hkdf)?;
    hkdf.expand(LABEL_C2S_NONCE, &mut client_to_server_nonce_base)
        .map_err(|_| CryptoError::Hkdf)?;
    hkdf.expand(LABEL_S2C_NONCE, &mut server_to_client_nonce_base)
        .map_err(|_| CryptoError::Hkdf)?;
    hkdf.expand(LABEL_RESUME, &mut resume_secret)
        .map_err(|_| CryptoError::Hkdf)?;
    hkdf.expand(LABEL_AUDIT, &mut audit_binding_key)
        .map_err(|_| CryptoError::Hkdf)?;
    hkdf.expand(LABEL_SESSION_ID, &mut session_id)
        .map_err(|_| CryptoError::Hkdf)?;

    Ok(SessionKeys {
        client_to_server_key,
        server_to_client_key,
        client_to_server_nonce_base,
        server_to_client_nonce_base,
        resume_secret,
        audit_binding_key,
        session_id: SessionId::from(session_id),
    })
}

pub fn encrypt_frame(
    keys: &SessionKeys,
    perspective: RolePerspective,
    sequence: u64,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let (key_bytes, nonce) = match perspective {
        RolePerspective::Client => (keys.client_to_server_key, keys.nonce(true, sequence)),
        RolePerspective::Server => (keys.server_to_client_key, keys.nonce(false, sequence)),
    };
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AeadFailure)
}

pub fn decrypt_frame(
    keys: &SessionKeys,
    perspective: RolePerspective,
    sequence: u64,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let (key_bytes, nonce) = match perspective {
        RolePerspective::Client => (keys.client_to_server_key, keys.nonce(true, sequence)),
        RolePerspective::Server => (keys.server_to_client_key, keys.nonce(false, sequence)),
    };
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::AeadFailure)
}

pub fn sign_payload(signing_key: &SigningKey, payload: &[u8]) -> [u8; 64] {
    signing_key.sign(payload).to_bytes()
}

pub fn verify_signature(
    peer_id: &PeerId,
    payload: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    let verifying_key = VerifyingKey::from_bytes(peer_id.as_bytes())
        .map_err(|_| CryptoError::InvalidIdentityKey)?;
    verifying_key
        .verify(payload, &Signature::from_bytes(signature))
        .map_err(|_| CryptoError::SignatureInvalid)
}

pub fn build_auth_init(
    identity: &IdentityKeypair,
    ephemeral: &EphemeralKeypair,
    transcript: &Transcript,
) -> Result<AuthInitPayload, CryptoError> {
    let mut freshness_nonce = [0; 16];
    OsRng.fill_bytes(&mut freshness_nonce);
    let mut signing_bytes = transcript.finalize().to_vec();
    signing_bytes.extend_from_slice(&ephemeral.public_bytes());
    signing_bytes.extend_from_slice(&freshness_nonce);
    Ok(AuthInitPayload {
        peer_id: identity.peer_id(),
        ephemeral_public_key: ephemeral.public_bytes(),
        freshness_nonce,
        signature: sign_payload(identity.signing_key(), &signing_bytes),
    })
}

pub fn build_auth_finish(
    identity: &IdentityKeypair,
    ephemeral: &EphemeralKeypair,
    transcript: &Transcript,
) -> Result<AuthFinishPayload, CryptoError> {
    let transcript_hash = transcript.finalize();
    let mut signing_bytes = transcript_hash.to_vec();
    signing_bytes.extend_from_slice(&ephemeral.public_bytes());
    Ok(AuthFinishPayload {
        peer_id: identity.peer_id(),
        ephemeral_public_key: ephemeral.public_bytes(),
        transcript_hash,
        signature: sign_payload(identity.signing_key(), &signing_bytes),
    })
}

pub fn verify_auth_init(
    payload: &AuthInitPayload,
    transcript: &Transcript,
) -> Result<(), CryptoError> {
    let mut signing_bytes = transcript.finalize().to_vec();
    signing_bytes.extend_from_slice(&payload.ephemeral_public_key);
    signing_bytes.extend_from_slice(&payload.freshness_nonce);
    verify_signature(&payload.peer_id, &signing_bytes, &payload.signature)
}

pub fn verify_auth_finish(
    payload: &AuthFinishPayload,
    _transcript: &Transcript,
) -> Result<(), CryptoError> {
    let mut signing_bytes = payload.transcript_hash.to_vec();
    signing_bytes.extend_from_slice(&payload.ephemeral_public_key);
    verify_signature(&payload.peer_id, &signing_bytes, &payload.signature)
}

pub fn transcript_hash_for_messages(messages: &[&[u8]]) -> [u8; 32] {
    let mut transcript = Transcript::default();
    for message in messages {
        transcript.push(message);
    }
    transcript.finalize()
}

pub fn receipt_hash(receipt_bytes: &[u8], previous_hash: &[u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(receipt_bytes);
    digest.update(previous_hash);
    digest.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vanta_wire::{BinaryCodec, HelloPayload};

    #[test]
    fn transcript_and_key_schedule_are_deterministic() {
        let hash = transcript_hash_for_messages(&[b"hello", b"world"]);
        let first = derive_session_keys([7; 32], hash).expect("keys");
        let second = derive_session_keys([7; 32], hash).expect("keys");
        assert_eq!(first.client_to_server_key, second.client_to_server_key);
        assert_eq!(first.server_to_client_key, second.server_to_client_key);
        assert_eq!(first.session_id, second.session_id);
        assert_ne!(first.client_to_server_key, [0; 32]);
        assert_ne!(*first.session_id.as_bytes(), [0; 16]);
    }

    #[test]
    fn auth_payloads_verify() {
        let identity = IdentityKeypair::from_bytes([3; 32]);
        let ephemeral = EphemeralKeypair::generate();
        let hello = HelloPayload {
            role: vanta_wire::WireRole::Initiator,
            supported_versions: vec![vanta_wire::Version { major: 0, minor: 0 }],
            suite_ids: vec![1],
            max_frame_size: 4096,
            transport_profiles: vec![vanta_wire::TransportProfile::Tcp],
            features: vec!["audit".into()],
            ordering_bits: 0b111,
        };
        let mut transcript = Transcript::default();
        transcript.push(&hello.encode().expect("hello"));
        let auth_init = build_auth_init(&identity, &ephemeral, &transcript).expect("auth init");
        verify_auth_init(&auth_init, &transcript).expect("verify auth init");
        transcript.push(&auth_init.encode().expect("encode auth init"));
        let auth_finish =
            build_auth_finish(&identity, &ephemeral, &transcript).expect("auth finish");
        verify_auth_finish(&auth_finish, &transcript).expect("verify auth finish");
    }
}
