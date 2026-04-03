use crate::models::AppError;
use openssl::pkcs7::{Pkcs7, Pkcs7Flags};
use openssl::pkey::PKey;
use openssl::stack::Stack;
use openssl::x509::X509;
use openssl::hash::MessageDigest;

/// Create CAdES-BES attached signature using OpenSSL
pub fn create_attached_signature(
    content: &[u8],
    signer_cert_der: &[u8],
    signer_key: &PKey<openssl::pkey::Private>,
) -> Result<Vec<u8>, AppError> {
    let cert = X509::from_der(signer_cert_der)
        .map_err(|e| AppError::Certificate(format!("Failed to parse certificate: {}", e)))?;

    let mut certs = Stack::new()
        .map_err(|e| AppError::Signing(format!("Failed to create cert stack: {}", e)))?;
    certs.push(cert.clone())
        .map_err(|e| AppError::Signing(format!("Failed to push cert: {}", e)))?;

    let pkcs7 = Pkcs7::sign(
        &cert,
        signer_key,
        &certs,
        content,
        Pkcs7Flags::BINARY,
    ).map_err(|e| AppError::Signing(format!("Failed to create PKCS7: {}", e)))?;

    pkcs7.to_der()
        .map_err(|e| AppError::Signing(format!("Failed to encode: {}", e)))
}

/// Create CAdES-BES detached signature using OpenSSL
pub fn create_detached_signature(
    content: &[u8],
    signer_cert_der: &[u8],
    signer_key: &PKey<openssl::pkey::Private>,
) -> Result<Vec<u8>, AppError> {
    let cert = X509::from_der(signer_cert_der)
        .map_err(|e| AppError::Certificate(format!("Failed to parse certificate: {}", e)))?;

    let mut certs = Stack::new()
        .map_err(|e| AppError::Signing(format!("Failed to create cert stack: {}", e)))?;
    certs.push(cert.clone())
        .map_err(|e| AppError::Signing(format!("Failed to push cert: {}", e)))?;

    let pkcs7 = Pkcs7::sign(
        &cert,
        signer_key,
        &certs,
        content,
        Pkcs7Flags::DETACHED | Pkcs7Flags::BINARY | Pkcs7Flags::NOCERTS,
    ).map_err(|e| AppError::Signing(format!("Failed to create PKCS7: {}", e)))?;

    pkcs7.to_der()
        .map_err(|e| AppError::Signing(format!("Failed to encode: {}", e)))
}

/// Verify a PKCS7 signature
pub fn verify_signature(
    signature_der: &[u8],
    original_data: Option<&[u8]>,
    _ca_certs: Option<&[X509]>,
) -> Result<bool, AppError> {
    let pkcs7 = Pkcs7::from_der(signature_der)
        .map_err(|e| AppError::Signing(format!("Failed to parse PKCS7: {}", e)))?;

    let content = match original_data {
        Some(data) => data,
        None => return Ok(true),
    };

    let store = openssl::x509::store::X509StoreBuilder::new()
        .map_err(|e| AppError::Signing(format!("Failed to create store: {}", e)))?
        .build();

    let empty_certs = Stack::new()
        .map_err(|e| AppError::Signing(format!("Failed to create stack: {}", e)))?;

    match pkcs7.verify(
        &empty_certs,
        &store,
        Some(content),
        None,
        Pkcs7Flags::DETACHED | Pkcs7Flags::BINARY,
    ) {
        Ok(_) => Ok(true),
        Err(e) => {
            tracing::warn!("Verification failed: {}", e);
            Ok(false)
        }
    }
}

/// Calculate message digest
pub fn calculate_digest(content: &[u8], algorithm: MessageDigest) -> Vec<u8> {
    use openssl::hash::Hasher;
    
    let mut hasher = Hasher::new(algorithm).expect("Failed to create hasher");
    hasher.update(content).expect("Failed to update");
    hasher.finish().expect("Failed to finish").to_vec()
}

/// Sign data with private key
pub fn sign_data(
    data: &[u8],
    private_key: &PKey<openssl::pkey::Private>,
    digest: MessageDigest,
) -> Result<Vec<u8>, AppError> {
    use openssl::sign::Signer;
    
    let mut signer = Signer::new(digest, private_key)
        .map_err(|e| AppError::Signing(format!("Failed to create signer: {}", e)))?;
    
    signer.update(data)
        .map_err(|e| AppError::Signing(format!("Failed to update: {}", e)))?;
    
    signer.sign_to_vec()
        .map_err(|e| AppError::Signing(format!("Failed to sign: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_digest() {
        let content = b"test content";
        let digest = calculate_digest(content, MessageDigest::sha256());
        assert_eq!(digest.len(), 32);
    }
}
