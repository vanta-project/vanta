use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use thiserror::Error;
use vanta_wire::{CapabilitySetId, SchemaFamilyId};

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("json error")]
    Json(#[from] serde_json::Error),
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("invalid verifier key")]
    InvalidVerifier,
    #[error("token collision for {kind}: {token:#010x}")]
    TokenCollision { kind: &'static str, token: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaManifest {
    pub family_id_hex: String,
    pub version_id: u32,
    pub name: String,
    pub fields: Vec<String>,
    pub optional_fields: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityManifest {
    pub set_id_hex: String,
    pub name: String,
    pub permissions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryManifest {
    pub version: u32,
    pub name: String,
    pub extension_namespaces: Vec<String>,
    pub schemas: Vec<SchemaManifest>,
    pub capabilities: Vec<CapabilityManifest>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRegistryManifest {
    pub manifest: RegistryManifest,
    pub signer_peer_id_hex: Option<String>,
    pub signature_base64: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledSchema {
    pub family_id: SchemaFamilyId,
    pub version_id: u32,
    pub name: String,
    pub descriptor_hash_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledCapability {
    pub capability_id: CapabilitySetId,
    pub name: String,
    pub descriptor_hash_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledRegistry {
    pub name: String,
    pub version: u32,
    pub schema_token: u32,
    pub capability_token: u32,
    pub extension_namespaces: Vec<String>,
    pub schemas: Vec<CompiledSchema>,
    pub capabilities: Vec<CompiledCapability>,
}

impl SignedRegistryManifest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RegistryError> {
        Ok(serde_json::to_vec(&self.manifest)?)
    }

    pub fn verify_signature(&self) -> Result<(), RegistryError> {
        match (&self.signer_peer_id_hex, &self.signature_base64) {
            (Some(peer_id_hex), Some(signature_base64)) => {
                let verifier = VerifyingKey::from_bytes(
                    &hex::decode(peer_id_hex)
                        .map_err(|_| RegistryError::InvalidVerifier)?
                        .try_into()
                        .map_err(|_| RegistryError::InvalidVerifier)?,
                )
                .map_err(|_| RegistryError::InvalidVerifier)?;
                use base64::Engine;
                let signature_bytes = base64::engine::general_purpose::STANDARD
                    .decode(signature_base64)
                    .map_err(|_| RegistryError::InvalidVerifier)?;
                let signature = Signature::try_from(signature_bytes.as_slice())
                    .map_err(|_| RegistryError::InvalidVerifier)?;
                verifier
                    .verify(&self.canonical_bytes()?, &signature)
                    .map_err(|_| RegistryError::SignatureInvalid)
            }
            _ => Ok(()),
        }
    }
}

pub fn compile_manifest(
    envelope: &SignedRegistryManifest,
) -> Result<CompiledRegistry, RegistryError> {
    envelope.verify_signature()?;

    let mut schema_tokens = HashSet::new();
    let mut capability_tokens = HashSet::new();

    let mut schemas = Vec::with_capacity(envelope.manifest.schemas.len());
    for schema in &envelope.manifest.schemas {
        let family_bytes: [u8; 8] = hex::decode(&schema.family_id_hex)
            .unwrap_or_default()
            .try_into()
            .unwrap_or([0; 8]);
        let canonical = serde_json::to_vec(schema)?;
        let descriptor_hash = Sha256::digest(&canonical);
        let token = truncate_token(&descriptor_hash);
        if !schema_tokens.insert(token) {
            return Err(RegistryError::TokenCollision {
                kind: "schema",
                token,
            });
        }
        schemas.push(CompiledSchema {
            family_id: SchemaFamilyId::from(family_bytes),
            version_id: schema.version_id,
            name: schema.name.clone(),
            descriptor_hash_hex: hex::encode(descriptor_hash),
        });
    }

    let mut capabilities = Vec::with_capacity(envelope.manifest.capabilities.len());
    for capability in &envelope.manifest.capabilities {
        let capability_bytes: [u8; 8] = hex::decode(&capability.set_id_hex)
            .unwrap_or_default()
            .try_into()
            .unwrap_or([0; 8]);
        let canonical = serde_json::to_vec(capability)?;
        let descriptor_hash = Sha256::digest(&canonical);
        let token = truncate_token(&descriptor_hash);
        if !capability_tokens.insert(token) {
            return Err(RegistryError::TokenCollision {
                kind: "capability",
                token,
            });
        }
        capabilities.push(CompiledCapability {
            capability_id: CapabilitySetId::from(capability_bytes),
            name: capability.name.clone(),
            descriptor_hash_hex: hex::encode(descriptor_hash),
        });
    }

    let schema_token = aggregate_token(
        schemas
            .iter()
            .map(|schema| schema.descriptor_hash_hex.as_str()),
    );
    let capability_token = aggregate_token(
        capabilities
            .iter()
            .map(|capability| capability.descriptor_hash_hex.as_str()),
    );

    Ok(CompiledRegistry {
        name: envelope.manifest.name.clone(),
        version: envelope.manifest.version,
        schema_token,
        capability_token,
        extension_namespaces: envelope.manifest.extension_namespaces.clone(),
        schemas,
        capabilities,
    })
}

pub fn truncate_token(hash: &[u8]) -> u32 {
    u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
}

fn aggregate_token<'a>(hashes: impl Iterator<Item = &'a str>) -> u32 {
    let mut digest = Sha256::new();
    for hash in hashes {
        digest.update(hash.as_bytes());
    }
    truncate_token(&digest.finalize())
}

#[derive(Clone, Debug, Default)]
pub struct RegistryIndex {
    by_schema_name: HashMap<String, CompiledSchema>,
    by_capability_name: HashMap<String, CompiledCapability>,
}

impl RegistryIndex {
    pub fn build(compiled: &CompiledRegistry) -> Self {
        let by_schema_name = compiled
            .schemas
            .iter()
            .cloned()
            .map(|schema| (schema.name.clone(), schema))
            .collect();
        let by_capability_name = compiled
            .capabilities
            .iter()
            .cloned()
            .map(|capability| (capability.name.clone(), capability))
            .collect();
        Self {
            by_schema_name,
            by_capability_name,
        }
    }

    pub fn schema(&self, name: &str) -> Option<&CompiledSchema> {
        self.by_schema_name.get(name)
    }

    pub fn capability(&self, name: &str) -> Option<&CompiledCapability> {
        self.by_capability_name.get(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_manifest_derives_tokens() {
        let manifest = SignedRegistryManifest {
            manifest: RegistryManifest {
                version: 1,
                name: "core".into(),
                extension_namespaces: vec!["vanta.core".into()],
                schemas: vec![SchemaManifest {
                    family_id_hex: "0102030405060708".into(),
                    version_id: 1,
                    name: "demo.command".into(),
                    fields: vec!["op".into(), "body".into()],
                    optional_fields: vec!["trace".into()],
                }],
                capabilities: vec![CapabilityManifest {
                    set_id_hex: "1112131415161718".into(),
                    name: "mutate".into(),
                    permissions: vec!["command.apply".into()],
                }],
                metadata: BTreeMap::new(),
            },
            signer_peer_id_hex: None,
            signature_base64: None,
        };
        let compiled = compile_manifest(&manifest).expect("compile");
        assert_ne!(compiled.schema_token, 0);
        assert_ne!(compiled.capability_token, 0);
        assert_eq!(compiled.schemas[0].name, "demo.command");
    }
}
