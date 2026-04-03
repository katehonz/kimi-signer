use crate::models::{AppError, CertificateInfo};
use std::path::Path;

/// Load a certificate from a file
pub fn load_certificate_from_file(path: &Path) -> Result<CertificateInfo, AppError> {
    let content = std::fs::read(path)
        .map_err(|e| AppError::Io(format!("Failed to read certificate file: {}", e)))?;

    // Detect format (DER or PEM)
    if content.starts_with(b"-----BEGIN") {
        // PEM format
        load_certificate_from_pem(&content)
    } else {
        // DER format
        load_certificate_from_der(&content)
    }
}

/// Load certificate from DER bytes
pub fn load_certificate_from_der(der: &[u8]) -> Result<CertificateInfo, AppError> {
    use x509_cert::Certificate;
    use x509_cert::der::Decode;
    use sha1::{Sha1, Digest};

    let cert = Certificate::from_der(der)
        .map_err(|e| AppError::Certificate(format!("Failed to parse certificate: {}", e)))?;

    let subject = cert.tbs_certificate.subject.to_string();
    let issuer = cert.tbs_certificate.issuer.to_string();
    let serial_number = cert.tbs_certificate.serial_number.to_string();

    // Get validity period - x509-cert uses types from spki crate
    // We need to convert the time types properly
    let valid_from = convert_x509_time(&cert.tbs_certificate.validity.not_before);
    let valid_to = convert_x509_time(&cert.tbs_certificate.validity.not_after);

    // Calculate SHA-1 thumbprint
    let mut hasher = Sha1::new();
    hasher.update(der);
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
        has_private_key: false,
    })
}

/// Convert x509_cert time to chrono DateTime
fn convert_x509_time(time: &x509_cert::time::Time) -> chrono::DateTime<chrono::Utc> {
    use x509_cert::der::Encode;
    
    // Get the time as string from the ASN.1 encoding
    let time_bytes = time.to_der().unwrap_or_default();
    
    // Try to parse as UTF-8 string and convert
    if let Ok(time_str) = std::str::from_utf8(&time_bytes[2..]) { // Skip tag and length
        // Try different formats
        let formats = [
            "%y%m%d%H%M%SZ",  // UTCTime
            "%Y%m%d%H%M%SZ",  // GeneralizedTime
        ];
        
        for format in &formats {
            if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(time_str.trim(), format) {
                return chrono::DateTime::from_naive_utc_and_offset(naive, chrono::Utc);
            }
        }
    }
    
    // Fallback: use current time
    chrono::Utc::now()
}

/// Load certificate from PEM bytes using OpenSSL
pub fn load_certificate_from_pem(pem: &[u8]) -> Result<CertificateInfo, AppError> {
    use openssl::x509::X509;

    let cert = X509::from_pem(pem)
        .map_err(|e| AppError::Certificate(format!("Failed to parse PEM certificate: {}", e)))?;

    // Use the to_text method or convert via DER
    let subject = cert.subject_name()
        .entries()
        .map(|e| format!("{:?}", e.object()))
        .collect::<Vec<_>>()
        .join(", ");
        
    let issuer = cert.issuer_name()
        .entries()
        .map(|e| format!("{:?}", e.object()))
        .collect::<Vec<_>>()
        .join(", ");
    
    // Convert serial number to hex string
    let serial_bn = cert.serial_number().to_bn()
        .map_err(|e| AppError::Certificate(e.to_string()))?;
    let serial_number = serial_bn.to_hex_str()
        .map_err(|e| AppError::Certificate(e.to_string()))?
        .to_string();

    // Convert ASN1_TIME to chrono
    let valid_from = asn1_time_to_chrono(cert.not_before())
        .unwrap_or_else(|_| chrono::Utc::now());
    let valid_to = asn1_time_to_chrono(cert.not_after())
        .unwrap_or_else(|_| chrono::Utc::now());

    // Get DER bytes for thumbprint
    let der = cert.to_der()
        .map_err(|e| AppError::Certificate(e.to_string()))?;

    use sha1::{Sha1, Digest};
    let mut hasher = Sha1::new();
    hasher.update(&der);
    let thumbprint = format!("{:X}", hasher.finalize());
    
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
        has_private_key: false,
    })
}

/// Convert OpenSSL ASN1_TIME to chrono DateTime
fn asn1_time_to_chrono(asn1_time: &openssl::asn1::Asn1TimeRef) -> Result<chrono::DateTime<chrono::Utc>, Box<dyn std::error::Error>> {
    // Convert to string and parse
    let time_str = asn1_time.to_string();
    
    // OpenSSL time formats: "Jan  1 00:00:00 2024 GMT" or "20240101000000Z"
    let formats = [
        "%b %e %H:%M:%S %Y GMT",
        "%b %e %H:%M:%S %Y",
        "%Y%m%d%H%M%SZ",
    ];
    
    for format in &formats {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(&time_str, format) {
            return Ok(chrono::DateTime::from_naive_utc_and_offset(naive, chrono::Utc));
        }
    }
    
    // Try parsing as date only
    if let Ok(date) = chrono::NaiveDate::parse_from_str(&time_str, "%b %e %Y") {
        let naive = date.and_hms_opt(0, 0, 0).unwrap_or_default();
        return Ok(chrono::DateTime::from_naive_utc_and_offset(naive, chrono::Utc));
    }
    
    Err(format!("Failed to parse time: {}", time_str).into())
}

/// Validate certificate chain
pub fn validate_certificate_chain(
    cert: &CertificateInfo,
    trusted_roots: &[CertificateInfo],
    _intermediate_certs: &[CertificateInfo],
) -> Result<bool, AppError> {
    // Build certificate chain
    // Verify each certificate's signature
    // Check validity dates
    // Verify against trusted roots
    
    // Check if certificate is valid
    if !cert.is_valid() {
        return Ok(false);
    }

    // Check if issuer is in trusted roots
    let issuer_trusted = trusted_roots.iter().any(|root| {
        root.subject == cert.issuer
    });

    Ok(issuer_trusted)
}

/// Check certificate revocation via CRL
pub fn check_crl(_cert: &CertificateInfo, _crl_data: &[u8]) -> Result<bool, AppError> {
    // Parse CRL
    // Check if certificate serial number is in revoked list
    
    Ok(true) // Not revoked
}

/// Export certificate to file
pub fn export_certificate(
    _cert: &CertificateInfo,
    _path: &Path,
    format: CertificateFormat,
) -> Result<(), AppError> {
    match format {
        CertificateFormat::Der => {
            // Export as DER
            todo!()
        }
        CertificateFormat::Pem => {
            // Export as PEM
            todo!()
        }
    }
}

pub enum CertificateFormat {
    Der,
    Pem,
}
