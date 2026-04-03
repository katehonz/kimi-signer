use crate::models::{AppError, CertificateInfo};
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use openssl::pkey::PKey;

/// PKCS#11 Module wrapper for smart card/token operations
pub struct Pkcs11Module {
    pkcs11: Pkcs11,
    slot: Slot,
    session: Option<Session>,
}

/// Certificate with its DER bytes and private key handle
#[derive(Debug, Clone)]
pub struct TokenCertificate {
    pub info: CertificateInfo,
    pub der_bytes: Vec<u8>,
    pub private_key_handle: Option<ObjectHandle>,
    pub public_key_handle: Option<ObjectHandle>,
}

impl Pkcs11Module {
    /// Create a new PKCS#11 module from a library path
    pub fn new(library_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let pkcs11 = Pkcs11::new(library_path)?;
        pkcs11.initialize(CInitializeArgs::OsThreads)?;

        // Get the first available slot with a token
        let slots = pkcs11.get_slots_with_token()?;
        if slots.is_empty() {
            return Err("No token found. Please insert your smart card or USB token.".into());
        }
        let slot = slots[0];

        Ok(Self {
            pkcs11,
            slot,
            session: None,
        })
    }

    /// Get available slots
    pub fn get_slots(&self) -> Result<Vec<Slot>, Box<dyn std::error::Error>> {
        Ok(self.pkcs11.get_slots_with_token()?)
    }

    /// Get slot information
    pub fn get_slot_info(&self) -> Result<cryptoki::slot::SlotInfo, Box<dyn std::error::Error>> {
        Ok(self.pkcs11.get_slot_info(self.slot)?)
    }

    /// Open a session with the token
    pub fn open_session(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let session = self.pkcs11.open_rw_session(self.slot)?;
        self.session = Some(session);
        Ok(())
    }

    /// Login to the token with PIN
    pub fn login(&self, pin: &str) -> Result<(), AppError> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| AppError::Pkcs11("No session open".to_string()))?;

        let auth_pin = AuthPin::new(pin.into());
        session
            .login(UserType::User, Some(&auth_pin))
            .map_err(|e| AppError::Pkcs11(format!("Login failed: {}", e)))?;
        Ok(())
    }

    /// Logout from the token
    pub fn logout(&self) -> Result<(), AppError> {
        if let Some(ref session) = self.session {
            session
                .logout()
                .map_err(|e| AppError::Pkcs11(format!("Logout failed: {}", e)))?;
        }
        Ok(())
    }

    /// Enumerate certificates from the token
    pub fn enumerate_certificates(&self) -> Result<Vec<TokenCertificate>, AppError> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| AppError::Pkcs11("No session open".to_string()))?;

        // Find certificate objects
        let template = vec![Attribute::Class(ObjectClass::CERTIFICATE)];

        let objects = session
            .find_objects(&template)
            .map_err(|e| AppError::Pkcs11(format!("Failed to find objects: {}", e)))?;

        let mut certificates = Vec::new();

        for cert_handle in objects {
            // Get certificate attributes
            let attrs = session
                .get_attributes(
                    cert_handle,
                    &[
                        AttributeType::Value,
                        AttributeType::Label,
                        AttributeType::Id,
                    ],
                )
                .map_err(|e| AppError::Pkcs11(format!("Failed to get attributes: {}", e)))?;

            // Get certificate value (DER bytes)
            let cert_der = if let Some(Attribute::Value(der)) =
                attrs.iter().find(|a| matches!(a, Attribute::Value(_)))
            {
                der.clone()
            } else {
                continue;
            };

            // Get certificate ID for matching with private key
            let cert_id = attrs.iter().find_map(|a| {
                if let Attribute::Id(id) = a {
                    tracing::debug!("Certificate has Id: {:02x?}", id);
                    Some(id.clone())
                } else {
                    None
                }
            });

            // Parse certificate info
            match Self::parse_certificate(&cert_der) {
                Ok(info) => {
                    // Find corresponding private key
                    let private_key_handle = if let Some(ref id) = cert_id {
                        match self.find_private_key_by_id(session, id) {
                            Ok(handle) => {
                                tracing::info!("Found matching private key for certificate");
                                Some(handle)
                            }
                            Err(e) => {
                                tracing::warn!("No private key found with matching ID: {}", e);
                                None
                            }
                        }
                    } else {
                        tracing::warn!("Certificate has no Id attribute");
                        None
                    };

                    certificates.push(TokenCertificate {
                        info,
                        der_bytes: cert_der,
                        private_key_handle,
                        public_key_handle: None,
                    });
                }
                Err(e) => {
                    tracing::warn!("Failed to parse certificate: {}", e);
                }
            }
        }

        Ok(certificates)
    }

    /// Sign data using the private key on the token
    pub fn sign(
        &self,
        private_key_handle: ObjectHandle,
        data: &[u8],
        mechanism: Mechanism,
    ) -> Result<Vec<u8>, AppError> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| AppError::Pkcs11("No session open".to_string()))?;

        session
            .sign(&mechanism, private_key_handle, data)
            .map_err(|e| AppError::Pkcs11(format!("Signing failed: {}", e)))
    }

    /// Sign data with RSA-PKCS mechanism (requires pre-formatted DigestInfo with padding)
    pub fn sign_rsa_pkcs(
        &self,
        private_key_handle: ObjectHandle,
        data: &[u8],
    ) -> Result<Vec<u8>, AppError> {
        self.sign(private_key_handle, data, Mechanism::RsaPkcs)
    }

    /// Sign data using SHA256-RSA-PKCS mechanism
    /// The token handles SHA-256 hashing and PKCS#1 v1.5 padding internally
    /// This is the most compatible method for CAdES signatures
    pub fn sign_sha256_rsa_pkcs(
        &self,
        private_key_handle: ObjectHandle,
        data: &[u8],
    ) -> Result<Vec<u8>, AppError> {
        tracing::info!("=== SIGNING DEBUG ===");
        tracing::info!("Data to sign (signed_attrs) length: {} bytes", data.len());
        tracing::info!("Data SHA256: {:02x?}", calculate_sha256(data));

        // Token has "Sign padding on-board: Yes" - use token's built-in padding
        tracing::info!("Using Sha256RsaPkcs (token handles padding)");
        match self.sign(private_key_handle, data, Mechanism::Sha256RsaPkcs) {
            Ok(sig) => {
                tracing::info!(
                    "Sha256RsaPkcs SUCCESS - signature size: {} bytes",
                    sig.len()
                );
                tracing::info!(
                    "Signature first 64 bytes: {:02x?}",
                    &sig[..std::cmp::min(64, sig.len())]
                );
                tracing::info!("=== END SIGNING DEBUG ===");
                return Ok(sig);
            }
            Err(e) => {
                tracing::warn!("Sha256RsaPkcs FAILED: {:?}", e);
                tracing::info!("=== END SIGNING DEBUG ===");
                return Err(e);
            }
        }
    }

    /// Sign SHA-256 hash with proper PKCS#1 v1.5 padding
    /// Creates: 0x00 0x01 0xFF...0xFF 0x00 [DigestInfo]
    pub fn sign_sha256_hash_with_padding(
        &self,
        private_key_handle: ObjectHandle,
        data: &[u8],
    ) -> Result<Vec<u8>, AppError> {
        // For RSA 2048, we need exactly 256 bytes
        let key_size = 256;

        // Create DigestInfo for SHA-256
        let data_hash = calculate_sha256(data);
        tracing::debug!("Data hash: {:02x?}", &data_hash[..8]);

        let digest_info = create_sha256_digest_info(&data_hash);
        tracing::debug!("DigestInfo length: {}", digest_info.len());

        // Calculate padding length
        let padding_len = key_size - 3 - digest_info.len();

        if padding_len < 8 {
            return Err(AppError::Pkcs11("Invalid padding length".to_string()));
        }

        // Build padded data according to PKCS#1 v1.5
        let mut padded_data = Vec::with_capacity(key_size);
        padded_data.push(0x00); // Leading zero
        padded_data.push(0x01); // Block type 01 (private key op)
        padded_data.extend(vec![0xFF; padding_len]); // Padding
        padded_data.push(0x00); // Separator
        padded_data.extend_from_slice(&digest_info); // DigestInfo

        tracing::debug!("Padded data length: {}", padded_data.len());
        tracing::debug!("Padded data prefix: {:02x?}", &padded_data[..10]);

        // Sign with RSA-PKCS (raw RSA operation)
        let sig = self.sign(private_key_handle, &padded_data, Mechanism::RsaPkcs)?;
        tracing::debug!("Signature length: {}", sig.len());
        Ok(sig)
    }

    /// Sign using ECDSA if available (for ECC keys)
    pub fn sign_ecdsa(
        &self,
        private_key_handle: ObjectHandle,
        data: &[u8],
    ) -> Result<Vec<u8>, AppError> {
        let hash = calculate_sha256(data);
        self.sign(private_key_handle, &hash, Mechanism::Ecdsa)
    }

    /// Get the key size from the token
    fn get_key_size(&self, key_handle: ObjectHandle) -> Result<usize, AppError> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| AppError::Pkcs11("No session open".to_string()))?;

        // Query the key attributes
        let attrs = session
            .get_attributes(key_handle, &[cryptoki::object::AttributeType::Modulus])
            .map_err(|e| AppError::Pkcs11(format!("Failed to get key attributes: {}", e)))?;

        if let Some(cryptoki::object::Attribute::Modulus(modulus)) = attrs.get(0) {
            // Modulus length in bits
            Ok(modulus.len())
        } else {
            // Default to RSA 2048 (256 bytes)
            Ok(256)
        }
    }

    /// Find private key by ID
    fn find_private_key_by_id(
        &self,
        session: &Session,
        key_id: &[u8],
    ) -> Result<ObjectHandle, Box<dyn std::error::Error>> {
        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Id(key_id.to_vec()),
        ];

        let objects = session.find_objects(&template)?;

        if objects.is_empty() {
            return Err("No private key found with matching ID".into());
        }

        Ok(objects[0])
    }

    /// Find private key corresponding to a certificate
    pub fn find_private_key(&self, cert: &TokenCertificate) -> Result<ObjectHandle, AppError> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| AppError::Pkcs11("No session open".to_string()))?;

        if let Some(handle) = cert.private_key_handle {
            tracing::info!("Using certificate-matched private key handle");
            return Ok(handle);
        }

        tracing::error!(
            "No private key handle from certificate ID matching - refusing to use arbitrary key"
        );
        return Err(AppError::Pkcs11(
            "Could not find private key matching certificate ID".to_string(),
        ));
    }

    /// Parse X.509 certificate from DER bytes
    fn parse_certificate(cert_der: &[u8]) -> Result<CertificateInfo, AppError> {
        use sha1::{Digest, Sha1};
        use x509_cert::der::Decode;
        use x509_cert::Certificate;

        let cert = Certificate::from_der(cert_der)
            .map_err(|e| AppError::Certificate(format!("Failed to parse certificate: {}", e)))?;

        let subject = cert.tbs_certificate.subject.to_string();
        let issuer = cert.tbs_certificate.issuer.to_string();
        let serial_number = cert.tbs_certificate.serial_number.to_string();

        let valid_from = convert_time(&cert.tbs_certificate.validity.not_before);
        let valid_to = convert_time(&cert.tbs_certificate.validity.not_after);

        // Calculate thumbprint (SHA-1)
        let mut hasher = Sha1::new();
        hasher.update(cert_der);
        let thumbprint = format!("{:X}", hasher.finalize());

        // Format thumbprint with colons
        let thumbprint = thumbprint
            .chars()
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join(":");

        Ok(CertificateInfo {
            subject,
            issuer,
            serial_number,
            valid_from,
            valid_to,
            thumbprint,
            has_private_key: true,
        })
    }
}

/// Calculate SHA-256 hash
fn calculate_sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Create SHA-256 DigestInfo structure according to PKCS#1 v1.5
///
/// DigestInfo ::= SEQUENCE {
///     digestAlgorithm AlgorithmIdentifier,
///     digest OCTET STRING
/// }
pub fn create_sha256_digest_info(digest: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();

    // SEQUENCE tag and length (will be calculated)
    result.push(0x30);

    // AlgorithmIdentifier for SHA-256
    // SEQUENCE { OID (2.16.840.1.101.3.4.2.1), NULL }
    let algo_id = vec![
        0x30, 0x0d, // SEQUENCE, length 13
        0x06, 0x09, // OID, length 9
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
        0x01, // SHA-256 OID (2.16.840.1.101.3.4.2.1)
        0x05, 0x00, // NULL
    ];

    // digest OCTET STRING
    let mut digest_octet = Vec::new();
    digest_octet.push(0x04); // OCTET STRING tag
    digest_octet.push(digest.len() as u8); // Length
    digest_octet.extend_from_slice(digest);

    // Total content length
    let content_len = algo_id.len() + digest_octet.len();

    if content_len < 128 {
        result.push(content_len as u8);
    } else {
        // Long form length
        let len_bytes = content_len.to_be_bytes();
        let len_start = len_bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(len_bytes.len() - 1);
        result.push(0x80 | ((len_bytes.len() - len_start) as u8));
        result.extend_from_slice(&len_bytes[len_start..]);
    }

    result.extend_from_slice(&algo_id);
    result.extend_from_slice(&digest_octet);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_digest_info() {
        let hash = vec![0u8; 32];
        let digest_info = create_sha256_digest_info(&hash);
        assert!(!digest_info.is_empty());
        assert_eq!(digest_info[0], 0x30); // SEQUENCE tag
    }
}

/// Convert x509_cert Time to chrono DateTime
fn convert_time(time: &x509_cert::time::Time) -> chrono::DateTime<chrono::Utc> {
    use x509_cert::der::Encode;

    // Encode to DER and extract the time string
    let der_bytes = match time.to_der() {
        Ok(bytes) => bytes,
        Err(_) => return chrono::Utc::now(),
    };

    // Skip tag (1 byte) and length (1-2 bytes depending on value)
    let content_start = if der_bytes[1] & 0x80 == 0 {
        2 // Short form length
    } else {
        2 + (der_bytes[1] & 0x7F) as usize // Long form length
    };

    if let Ok(time_str) = std::str::from_utf8(&der_bytes[content_start..]) {
        // Try parsing UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ)
        if time_str.len() == 13 && time_str.ends_with('Z') {
            // UTCTime format
            if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(time_str, "%y%m%d%H%M%SZ") {
                return chrono::DateTime::from_naive_utc_and_offset(naive, chrono::Utc);
            }
        } else if time_str.len() >= 15 && time_str.ends_with('Z') {
            // GeneralizedTime format
            if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(time_str, "%Y%m%d%H%M%SZ") {
                return chrono::DateTime::from_naive_utc_and_offset(naive, chrono::Utc);
            }
        }
    }

    chrono::Utc::now()
}

/// Mock private key for testing (when no token is available)
pub struct MockPrivateKey;

impl MockPrivateKey {
    /// Create a mock PKey for testing
    pub fn create() -> Result<PKey<openssl::pkey::Private>, AppError> {
        // Generate a temporary RSA key for testing
        let rsa = openssl::rsa::Rsa::generate(2048)
            .map_err(|e| AppError::Signing(format!("Failed to generate test key: {}", e)))?;

        PKey::from_rsa(rsa).map_err(|e| AppError::Signing(format!("Failed to create PKey: {}", e)))
    }
}
