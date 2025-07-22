use crate::api_types::Authorization;
use bincode::Options;
use ciborium::{de::from_reader, ser::into_writer};
use coset::{iana, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder};
use data_encoding::Encoding;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Display;
use thiserror::Error;

pub const DEFAULT_EXPIRATION_SECONDS: u64 = 60 * 60; // 60 minutes

/// This newtype is introduced to distinguish between a u64 meant to represent the current time
/// (currently passed as a raw u64), and a u64 meant to represent an expiration time.
/// We introduce this to intentonally break callers to `gen_doc_token` that do not explicitly
/// update to pass an expiration time, so that calls that use the old signature to pass a current
/// time do not compile.
/// Unit is milliseconds since Jan 1, 1970.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ExpirationTimeEpochMillis(pub u64);

impl ExpirationTimeEpochMillis {
    pub fn max() -> Self {
        Self(u64::MAX)
    }
}

#[derive(Serialize, Deserialize, Default)]
struct CwtClaims {
    #[serde(skip_serializing_if = "Option::is_none", rename = "1")]
    iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "4")]
    exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "6")]
    iat: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none", rename = "100")]
    kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "101")]
    doc_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "102")]
    file_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "103")]
    authorization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "104")]
    content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "105")]
    content_length: Option<u64>,
}

/// This is a custom base64 encoder that is equivalent to BASE64URL_NOPAD for encoding,
/// but is tolerant when decoding of the “standard” alphabet and also of padding.
/// This is necessary for now because we used to use standard base64 encoding with padding,
/// but we can eventually remove it.
///
/// ```
/// use data_encoding::{Specification, BASE64URL_NOPAD, Translate};
/// let spec = Specification {
///     ignore: "=".to_string(),
///     translate: Translate {
///         from: "/+".to_string(),
///         to: "_-".to_string(),
///     },
///     ..BASE64URL_NOPAD.specification()
/// };
/// use y_sweet_core::auth::BASE64_CUSTOM;
/// assert_eq!(BASE64_CUSTOM, spec.encoding().unwrap());
/// ```
pub const BASE64_CUSTOM: Encoding = Encoding::internal_new(&[
    65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88,
    89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114,
    115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 45, 95, 65, 66,
    67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
    97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
    116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 45, 95, 65, 66, 67,
    68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97,
    98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
    117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 45, 95, 65, 66, 67, 68,
    69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98,
    99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117,
    118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 45, 95, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 62, 128, 62, 128, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 128, 128, 128, 129, 128,
    128, 128, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
    24, 25, 128, 128, 128, 128, 63, 128, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
    40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 30, 0,
]);

#[derive(Error, Debug, PartialEq, Eq)]
pub enum AuthError {
    #[error("The token is not a valid format")]
    InvalidToken,
    #[error("The token is expired")]
    Expired,
    #[error("The token is not valid for the requested resource")]
    InvalidResource,
    #[error("The token signature is invalid")]
    InvalidSignature,
    #[error("The key ID did not match")]
    KeyMismatch,
}

#[derive(Serialize, Deserialize, PartialEq, PartialOrd, Debug, Clone)]
pub struct Authenticator {
    #[serde(with = "b64")]
    private_key: Vec<u8>,
    key_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct DocPermission {
    pub doc_id: String,
    pub authorization: Authorization,
}

#[derive(Serialize, Deserialize)]
pub struct FilePermission {
    pub file_hash: String,
    pub authorization: Authorization,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub doc_id: String,
}

#[derive(Serialize, Deserialize)]
pub enum Permission {
    Server,
    Doc(DocPermission),
    File(FilePermission),
}

#[derive(Serialize, Deserialize)]
pub struct Payload {
    pub payload: Permission,
    pub expiration_millis: Option<ExpirationTimeEpochMillis>,
}

#[derive(Serialize, Deserialize)]
pub struct AuthenticatedRequest {
    pub payload: Payload,
    pub token: Vec<u8>,
}

fn bincode_encode<T: Serialize>(value: &T) -> Result<Vec<u8>, bincode::Error> {
    // This uses different defaults than the default bincode::serialize() function.
    bincode::DefaultOptions::new().serialize(&value)
}

fn bincode_decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, bincode::Error> {
    // This uses different defaults than the default bincode::deserialize() function.
    bincode::DefaultOptions::new().deserialize(bytes)
}

fn b64_encode(bytes: &[u8]) -> String {
    BASE64_CUSTOM.encode(bytes)
}

fn b64_decode(input: &str) -> Result<Vec<u8>, AuthError> {
    BASE64_CUSTOM
        .decode(input.as_bytes())
        .map_err(|_| AuthError::InvalidToken)
}

fn ed25519_keypair(secret: &[u8]) -> Keypair {
    let seed = Sha256::digest(secret);
    let sk = SecretKey::from_bytes(&seed[..32]).expect("32 bytes");
    let pk: PublicKey = (&sk).into();
    Keypair {
        secret: sk,
        public: pk,
    }
}

fn payload_to_claims(payload: &Payload) -> CwtClaims {
    let mut claims = CwtClaims::default();
    claims.iss = Some("y-sweet".to_string());
    if let Some(exp) = payload.expiration_millis {
        claims.exp = Some(exp.0 / 1000);
    }
    match &payload.payload {
        Permission::Server => {
            claims.kind = Some("server".into());
        }
        Permission::Doc(doc) => {
            claims.kind = Some("doc".into());
            claims.doc_id = Some(doc.doc_id.clone());
            claims.authorization = Some(match doc.authorization {
                Authorization::ReadOnly => "read".into(),
                Authorization::Full => "full".into(),
            });
        }
        Permission::File(f) => {
            claims.kind = Some("file".into());
            claims.file_hash = Some(f.file_hash.clone());
            claims.doc_id = Some(f.doc_id.clone());
            claims.authorization = Some(match f.authorization {
                Authorization::ReadOnly => "read".into(),
                Authorization::Full => "full".into(),
            });
            claims.content_type = f.content_type.clone();
            claims.content_length = f.content_length;
        }
    }
    claims
}

fn claims_to_payload(claims: CwtClaims) -> Result<Payload, AuthError> {
    let expiration = claims.exp.map(|e| ExpirationTimeEpochMillis(e * 1000));
    let perm = match claims.kind.as_deref() {
        Some("server") => Permission::Server,
        Some("doc") => Permission::Doc(DocPermission {
            doc_id: claims.doc_id.ok_or(AuthError::InvalidToken)?,
            authorization: match claims.authorization.as_deref() {
                Some("read") => Authorization::ReadOnly,
                Some("full") => Authorization::Full,
                _ => return Err(AuthError::InvalidToken),
            },
        }),
        Some("file") => Permission::File(FilePermission {
            file_hash: claims.file_hash.ok_or(AuthError::InvalidToken)?,
            doc_id: claims.doc_id.ok_or(AuthError::InvalidToken)?,
            authorization: match claims.authorization.as_deref() {
                Some("read") => Authorization::ReadOnly,
                Some("full") => Authorization::Full,
                _ => return Err(AuthError::InvalidToken),
            },
            content_type: claims.content_type,
            content_length: claims.content_length,
        }),
        _ => return Err(AuthError::InvalidToken),
    };
    Ok(Payload {
        payload: perm,
        expiration_millis: expiration,
    })
}

mod b64 {
    use super::*;
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&b64_encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        b64_decode(&s).map_err(de::Error::custom)
    }
}

impl Payload {
    pub fn new(payload: Permission) -> Self {
        Self {
            payload,
            expiration_millis: None,
        }
    }

    pub fn new_with_expiration(
        payload: Permission,
        expiration_millis: ExpirationTimeEpochMillis,
    ) -> Self {
        Self {
            payload,
            expiration_millis: Some(expiration_millis),
        }
    }
}

fn hash(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    result.to_vec()
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct KeyId(String);

#[derive(Error, Debug, PartialEq, Eq)]
pub enum KeyIdError {
    #[error("The key ID cannot be an empty string")]
    EmptyString,
    #[error("The key ID contains an invalid character: {ch}")]
    InvalidCharacter { ch: char },
}

impl KeyId {
    pub fn new(key_id: String) -> Result<Self, KeyIdError> {
        if key_id.is_empty() {
            return Err(KeyIdError::EmptyString);
        }

        let valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for ch in key_id.chars() {
            if !valid_chars.contains(ch) {
                return Err(KeyIdError::InvalidCharacter { ch });
            }
        }

        Ok(Self(key_id))
    }
}

impl Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for KeyId {
    type Error = KeyIdError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value.to_string())
    }
}

impl Authenticator {
    pub fn new(private_key: &str) -> Result<Self, AuthError> {
        let private_key = b64_decode(private_key)?;

        Ok(Self {
            private_key,
            key_id: None,
        })
    }

    pub fn server_token(&self) -> String {
        self.sign(Payload::new(Permission::Server))
    }

    pub fn server_token_cwt(&self) -> String {
        self.sign_cwt(Payload::new(Permission::Server))
    }

    fn sign(&self, payload: Payload) -> String {
        let mut hash_payload =
            bincode_encode(&payload).expect("Bincode serialization should not fail.");
        hash_payload.extend_from_slice(&self.private_key);

        let token = hash(&hash_payload);

        let auth_req = AuthenticatedRequest { payload, token };

        let auth_enc = bincode_encode(&auth_req).expect("Bincode serialization should not fail.");
        let result = b64_encode(&auth_enc);
        if let Some(key_id) = &self.key_id {
            format!("{}.{}", key_id, result)
        } else {
            result
        }
    }

    fn sign_cwt(&self, payload: Payload) -> String {
        let claims = payload_to_claims(&payload);
        let mut buf = Vec::new();
        into_writer(&claims, &mut buf).expect("cbor encoding");
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .key_id(self.key_id.as_deref().unwrap_or("").as_bytes().to_vec())
            .build();
        let kp = ed25519_keypair(&self.private_key);
        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(buf)
            .create_signature(&[], |m| kp.sign(m).to_bytes().to_vec())
            .build();
        let cose_bytes = sign1.to_vec().expect("cbor");
        let token = b64_encode(&cose_bytes);
        if let Some(kid) = &self.key_id {
            format!("{}.{}", kid, token)
        } else {
            token
        }
    }

    fn verify(&self, token: &str, current_time: u64) -> Result<Payload, AuthError> {
        let token = if let Some((prefix, token)) = token.split_once('.') {
            if Some(prefix) != self.key_id.as_deref() {
                return Err(AuthError::KeyMismatch);
            }

            token
        } else {
            if self.key_id.is_some() {
                return Err(AuthError::KeyMismatch);
            }

            token
        };

        // Try new CWT format first
        if let Ok(payload) = self.verify_cwt_token(token, current_time) {
            return Ok(payload);
        }

        let auth_req: AuthenticatedRequest =
            bincode_decode(&b64_decode(token)?).or(Err(AuthError::InvalidToken))?;

        let mut payload =
            bincode_encode(&auth_req.payload).expect("Bincode serialization should not fail.");
        payload.extend_from_slice(&self.private_key);

        let expected_token = hash(&payload);

        if expected_token != auth_req.token {
            Err(AuthError::InvalidSignature)
        } else if auth_req
            .payload
            .expiration_millis
            .unwrap_or(ExpirationTimeEpochMillis::max())
            .0
            < current_time
        {
            Err(AuthError::Expired)
        } else {
            Ok(auth_req.payload)
        }
    }

    fn verify_cwt_token(&self, token: &str, current_time: u64) -> Result<Payload, AuthError> {
        let data = b64_decode(token)?;
        let cose: CoseSign1 = CoseSign1::from_slice(&data).map_err(|_| AuthError::InvalidToken)?;
        let payload = cose.payload.clone().ok_or(AuthError::InvalidToken)?;
        let kp = ed25519_keypair(&self.private_key);
        cose.verify_signature(&[], |sig, tbs| {
            let sig = Signature::from_bytes(sig).map_err(|_| AuthError::InvalidSignature)?;
            kp.public
                .verify(tbs, &sig)
                .map_err(|_| AuthError::InvalidSignature)
        })?;
        let claims: CwtClaims =
            from_reader(payload.as_slice()).map_err(|_| AuthError::InvalidToken)?;
        if let Some(exp) = claims.exp {
            if exp * 1000 < current_time {
                return Err(AuthError::Expired);
            }
        }
        claims_to_payload(claims)
    }

    pub fn with_key_id(self, key_id: KeyId) -> Self {
        Self {
            key_id: Some(key_id.0),
            ..self
        }
    }

    pub fn verify_server_token(
        &self,
        token: &str,
        current_time_epoch_millis: u64,
    ) -> Result<(), AuthError> {
        let payload = self.verify(token, current_time_epoch_millis)?;
        match payload {
            Payload {
                payload: Permission::Server,
                ..
            } => Ok(()),
            _ => Err(AuthError::InvalidResource),
        }
    }

    pub fn private_key(&self) -> String {
        b64_encode(&self.private_key)
    }

    pub fn gen_doc_token(
        &self,
        doc_id: &str,
        authorization: Authorization,
        expiration_time: ExpirationTimeEpochMillis,
    ) -> String {
        let payload = Payload::new_with_expiration(
            Permission::Doc(DocPermission {
                doc_id: doc_id.to_string(),
                authorization,
            }),
            expiration_time,
        );
        self.sign(payload)
    }

    pub fn gen_doc_token_cwt(
        &self,
        doc_id: &str,
        authorization: Authorization,
        expiration_time: ExpirationTimeEpochMillis,
    ) -> String {
        let payload = Payload::new_with_expiration(
            Permission::Doc(DocPermission {
                doc_id: doc_id.to_string(),
                authorization,
            }),
            expiration_time,
        );
        self.sign_cwt(payload)
    }

    pub fn gen_file_token(
        &self,
        file_hash: &str,
        doc_id: &str,
        authorization: Authorization,
        expiration_time: ExpirationTimeEpochMillis,
        content_type: Option<&str>,
        content_length: Option<u64>,
    ) -> String {
        let payload = Payload::new_with_expiration(
            Permission::File(FilePermission {
                file_hash: file_hash.to_string(),
                doc_id: doc_id.to_string(),
                authorization,
                content_type: content_type.map(|s| s.to_string()),
                content_length,
            }),
            expiration_time,
        );
        self.sign(payload)
    }

    pub fn gen_file_token_cwt(
        &self,
        file_hash: &str,
        doc_id: &str,
        authorization: Authorization,
        expiration_time: ExpirationTimeEpochMillis,
        content_type: Option<&str>,
        content_length: Option<u64>,
    ) -> String {
        let payload = Payload::new_with_expiration(
            Permission::File(FilePermission {
                file_hash: file_hash.to_string(),
                doc_id: doc_id.to_string(),
                authorization,
                content_type: content_type.map(|s| s.to_string()),
                content_length,
            }),
            expiration_time,
        );
        self.sign_cwt(payload)
    }

    fn verify_token(
        &self,
        token: &str,
        current_time_epoch_millis: u64,
    ) -> Result<Permission, AuthError> {
        let payload = self.verify(token, current_time_epoch_millis)?;
        Ok(payload.payload)
    }

    pub fn verify_doc_token(
        &self,
        token: &str,
        doc: &str,
        current_time_epoch_millis: u64,
    ) -> Result<Authorization, AuthError> {
        let payload = self.verify_token(token, current_time_epoch_millis)?;

        match payload {
            Permission::Doc(doc_permission) => {
                if doc_permission.doc_id == doc {
                    Ok(doc_permission.authorization)
                } else {
                    Err(AuthError::InvalidResource)
                }
            }
            Permission::File(file_permission) => {
                // Only check for file tokens using doc_id, not file_hash
                // This prevents document tokens from being misinterpreted
                if file_permission.doc_id == doc {
                    Ok(file_permission.authorization)
                } else {
                    Err(AuthError::InvalidResource)
                }
            }
            Permission::Server => Ok(Authorization::Full), // Server tokens can access any doc.
        }
    }

    pub fn verify_file_token(
        &self,
        token: &str,
        file_hash: &str,
        current_time_epoch_millis: u64,
    ) -> Result<Authorization, AuthError> {
        let payload = self.verify_token(token, current_time_epoch_millis)?;

        match payload {
            Permission::File(file_permission) => {
                if file_permission.file_hash == file_hash {
                    Ok(file_permission.authorization)
                } else {
                    Err(AuthError::InvalidResource)
                }
            }
            Permission::Server => Ok(Authorization::Full), // Server tokens can access any file
            _ => Err(AuthError::InvalidResource),
        }
    }

    pub fn verify_file_token_for_doc(
        &self,
        token: &str,
        doc_id: &str,
        current_time_epoch_millis: u64,
    ) -> Result<Authorization, AuthError> {
        let payload = self.verify_token(token, current_time_epoch_millis)?;

        match payload {
            Permission::File(file_permission) => {
                if file_permission.doc_id == doc_id {
                    Ok(file_permission.authorization)
                } else {
                    Err(AuthError::InvalidResource)
                }
            }
            Permission::Doc(doc_permission) => {
                // Allow Doc tokens to perform file operations for their doc_id
                if doc_permission.doc_id == doc_id {
                    Ok(doc_permission.authorization)
                } else {
                    Err(AuthError::InvalidResource)
                }
            }
            Permission::Server => Ok(Authorization::Full), // Server tokens can access any doc
        }
    }

    pub fn file_token_metadata(
        &self,
        token: &str,
    ) -> Result<Option<(String, Option<String>, Option<u64>)>, AuthError> {
        let payload = self.decode_token(token)?;

        match payload.payload {
            Permission::File(file_permission) => Ok(Some((
                file_permission.doc_id,
                file_permission.content_type,
                file_permission.content_length,
            ))),
            _ => Ok(None), // Not a file token
        }
    }

    pub fn gen_key() -> Result<Authenticator, AuthError> {
        let key = rand::thread_rng().gen::<[u8; 30]>();
        let key = b64_encode(&key);

        let authenticator = Authenticator::new(&key)?;
        Ok(authenticator)
    }

    pub fn decode_token(&self, token: &str) -> Result<Payload, AuthError> {
        let token = if let Some((_, token)) = token.split_once('.') {
            token
        } else {
            token
        };
        if let Ok(payload) = self.verify_cwt_token(token, 0) {
            return Ok(payload);
        }

        let auth_req: AuthenticatedRequest =
            bincode_decode(&b64_decode(token)?).or(Err(AuthError::InvalidToken))?;

        Ok(auth_req.payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_token_with_metadata() {
        let authenticator = Authenticator::gen_key().unwrap();
        let file_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let doc_id = "doc123";
        let content_type = "application/json";
        let content_length = 12345;

        // Generate token with content-type and length
        let token = authenticator.gen_file_token(
            file_hash,
            doc_id,
            Authorization::Full,
            ExpirationTimeEpochMillis(0),
            Some(content_type),
            Some(content_length),
        );

        // Verify the token works for file hash authentication
        assert!(matches!(
            authenticator.verify_file_token(&token, file_hash, 0),
            Ok(Authorization::Full)
        ));

        // Verify the token works for doc authentication
        assert!(matches!(
            authenticator.verify_file_token_for_doc(&token, doc_id, 0),
            Ok(Authorization::Full)
        ));

        // Decode the token and verify metadata
        let payload = authenticator.decode_token(&token).unwrap();
        if let Permission::File(file_permission) = payload.payload {
            assert_eq!(file_permission.file_hash, file_hash);
            assert_eq!(file_permission.doc_id, doc_id);
            assert_eq!(file_permission.content_type, Some(content_type.to_string()));
            assert_eq!(file_permission.content_length, Some(content_length));
        } else {
            panic!("Expected File permission type");
        }

        // Test file_token_metadata
        let metadata = authenticator.file_token_metadata(&token).unwrap().unwrap();
        assert_eq!(metadata.0, doc_id);
        assert_eq!(metadata.1, Some(content_type.to_string()));
        assert_eq!(metadata.2, Some(content_length));
    }

    #[test]
    fn test_file_token_without_metadata() {
        let authenticator = Authenticator::gen_key().unwrap();
        let file_hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let doc_id = "doc123";

        // Generate token without content-type and length
        let token = authenticator.gen_file_token(
            file_hash,
            doc_id,
            Authorization::Full,
            ExpirationTimeEpochMillis(0),
            None,
            None,
        );

        // Verify the token with file hash
        assert!(matches!(
            authenticator.verify_file_token(&token, file_hash, 0),
            Ok(Authorization::Full)
        ));

        // Verify the token with doc id
        assert!(matches!(
            authenticator.verify_file_token_for_doc(&token, doc_id, 0),
            Ok(Authorization::Full)
        ));

        // Decode the token and verify no metadata present
        let payload = authenticator.decode_token(&token).unwrap();
        if let Permission::File(file_permission) = payload.payload {
            assert_eq!(file_permission.file_hash, file_hash);
            assert_eq!(file_permission.doc_id, doc_id);
            assert_eq!(file_permission.content_type, None);
            assert_eq!(file_permission.content_length, None);
        } else {
            panic!("Expected File permission type");
        }
    }

    #[test]
    fn test_flex_b64() {
        let expect = [3, 242, 3, 248, 6, 220, 118];

        assert_eq!(b64_decode("A/ID+Abcdg==").unwrap(), expect);
        assert_eq!(b64_decode("A/ID+Abcdg").unwrap(), expect);

        assert_eq!(b64_decode("A_ID-Abcdg==").unwrap(), expect);
        assert_eq!(b64_decode("A_ID-Abcdg").unwrap(), expect);
    }

    #[test]
    fn test_b64_encode_options() {
        let data = [3, 242, 3, 248, 6, 220, 118];

        assert_eq!(b64_encode(&data), "A_ID-Abcdg");
    }

    #[test]
    fn test_simple_auth() {
        let authenticator = Authenticator::gen_key().unwrap();
        let token = authenticator.gen_doc_token(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(0),
        );
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", 0),
            Ok(Authorization::Full)
        ));
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", DEFAULT_EXPIRATION_SECONDS + 1),
            Err(AuthError::Expired)
        ));
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc456", 0),
            Err(AuthError::InvalidResource)
        ));
    }

    #[test]
    fn test_read_only_auth() {
        let authenticator = Authenticator::gen_key().unwrap();
        let token = authenticator.gen_doc_token(
            "doc123",
            Authorization::ReadOnly,
            ExpirationTimeEpochMillis(0),
        );
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", 0),
            Ok(Authorization::ReadOnly)
        ));
    }

    #[test]
    fn test_server_token_for_doc_auth() {
        let authenticator = Authenticator::gen_key().unwrap();
        let server_token = authenticator.server_token();
        assert!(matches!(
            authenticator.verify_doc_token(&server_token, "doc123", 0),
            Ok(Authorization::Full)
        ));
    }

    #[test]
    fn test_key_id() {
        let authenticator = Authenticator::gen_key()
            .unwrap()
            .with_key_id("myKeyId".try_into().unwrap());
        let token = authenticator.gen_doc_token(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(0),
        );
        assert!(
            token.starts_with("myKeyId."),
            "Token {} does not start with myKeyId.",
            token
        );
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", 0),
            Ok(Authorization::Full)
        ));

        let token = authenticator.server_token();
        assert!(
            token.starts_with("myKeyId."),
            "Token {} does not start with myKeyId.",
            token
        );
        assert_eq!(authenticator.verify_server_token(&token, 0), Ok(()));
    }

    #[test]
    fn test_construct_key_id() {
        assert_eq!(KeyId::new("".to_string()), Err(KeyIdError::EmptyString));
        assert_eq!(
            KeyId::new("*".to_string()),
            Err(KeyIdError::InvalidCharacter { ch: '*' })
        );
        assert_eq!(
            KeyId::new("myKeyId".to_string()),
            Ok(KeyId("myKeyId".to_string()))
        );
    }

    #[test]
    fn test_key_id_mismatch() {
        let authenticator = Authenticator::gen_key()
            .unwrap()
            .with_key_id("myKeyId".try_into().unwrap());
        let token = authenticator.gen_doc_token(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(0),
        );
        let token = token.replace("myKeyId.", "aDifferentKeyId.");
        assert!(token.starts_with("aDifferentKeyId."));
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", 0),
            Err(AuthError::KeyMismatch)
        ));
    }

    #[test]
    fn test_missing_key_id() {
        let authenticator = Authenticator::gen_key()
            .unwrap()
            .with_key_id("myKeyId".try_into().unwrap());
        let token = authenticator.gen_doc_token(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(0),
        );
        let token = token.replace("myKeyId.", "");
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", 0),
            Err(AuthError::KeyMismatch)
        ));
    }

    #[test]
    fn test_unexpected_key_id() {
        let authenticator = Authenticator::gen_key().unwrap();
        let token = authenticator.gen_doc_token(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(0),
        );
        let token = format!("unexpectedKeyId.{}", token);
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", 0),
            Err(AuthError::KeyMismatch)
        ));
    }

    #[test]
    fn test_invalid_signature() {
        let authenticator = Authenticator::gen_key().unwrap();
        let actual_payload = Payload::new(Permission::Doc(DocPermission {
            doc_id: "doc123".to_string(),
            authorization: Authorization::Full,
        }));
        let mut encoded_payload =
            bincode_encode(&actual_payload).expect("Bincode serialization should not fail.");
        encoded_payload.extend_from_slice(&authenticator.private_key);

        let token = hash(&encoded_payload);

        let auth_req = AuthenticatedRequest {
            payload: Payload::new(Permission::Doc(DocPermission {
                doc_id: "abc123".to_string(),
                authorization: Authorization::Full,
            })),
            token,
        };

        let auth_enc = bincode_encode(&auth_req).expect("Bincode serialization should not fail.");
        let signed = b64_encode(&auth_enc);

        assert!(matches!(
            authenticator.verify_doc_token(&signed, "doc123", 0),
            Err(AuthError::InvalidSignature)
        ));
        assert!(matches!(
            authenticator.verify_doc_token(&signed, "abc123", 0),
            Err(AuthError::InvalidSignature)
        ));
    }

    #[test]
    fn test_roundtrip_serde_authenticator() {
        let authenticator = Authenticator::gen_key().unwrap();
        let serialized = serde_json::to_string(&authenticator).unwrap();
        let deserialized: Authenticator = serde_json::from_str(&serialized).unwrap();
        assert_eq!(authenticator, deserialized);
    }

    #[test]
    fn test_doc_token_cwt() {
        let authenticator = Authenticator::gen_key().unwrap();
        let token = authenticator.gen_doc_token_cwt(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(0),
        );

        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", 0),
            Ok(Authorization::Full)
        ));

        let payload = authenticator.decode_token(&token).unwrap();
        match payload.payload {
            Permission::Doc(doc) => {
                assert_eq!(doc.doc_id, "doc123");
                assert_eq!(doc.authorization, Authorization::Full);
            }
            _ => panic!("Expected doc permission"),
        }
    }

    #[test]
    fn test_file_token_cwt() {
        let authenticator = Authenticator::gen_key().unwrap();
        let token = authenticator.gen_file_token_cwt(
            "hash",
            "doc123",
            Authorization::ReadOnly,
            ExpirationTimeEpochMillis(0),
            Some("text/plain"),
            Some(42),
        );

        assert!(matches!(
            authenticator.verify_file_token(&token, "hash", 0),
            Ok(Authorization::ReadOnly)
        ));

        let payload = authenticator.decode_token(&token).unwrap();
        match payload.payload {
            Permission::File(f) => {
                assert_eq!(f.file_hash, "hash");
                assert_eq!(f.doc_id, "doc123");
                assert_eq!(f.authorization, Authorization::ReadOnly);
                assert_eq!(f.content_type, Some("text/plain".to_string()));
                assert_eq!(f.content_length, Some(42));
            }
            _ => panic!("Expected file permission"),
        }
    }

    #[test]
    fn test_server_token_cwt() {
        let authenticator = Authenticator::gen_key().unwrap();
        let token = authenticator.server_token_cwt();

        assert!(matches!(authenticator.verify_server_token(&token, 0), Ok(())));
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", 0),
            Ok(Authorization::Full)
        ));
    }
}
