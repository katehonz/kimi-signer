//! CMS/PKCS#7 Builder for CAdES signatures
//!
//! This module builds CMS SignedData structures manually using ASN.1 DER encoding
//! because we cannot extract the private key from the token.

use crate::crypto::pkcs11::Pkcs11Module;
use crate::models::AppError;
use cryptoki::object::ObjectHandle;
use openssl::x509::X509;
use sha2::{Digest, Sha256};

/// Build a CAdES-BES detached signature using PKCS#11 for signing
///
/// This creates a CMS SignedData structure manually because we cannot
/// extract the private key from the token to use with OpenSSL.
pub fn build_cades_detached_signature(
    content: &[u8],
    signer_cert_der: &[u8],
    pkcs11: &Pkcs11Module,
    private_key_handle: ObjectHandle,
) -> Result<Vec<u8>, AppError> {
    tracing::info!(">>> build_cades_DETACHED_signature called");
    // Load the certificate
    let cert = X509::from_der(signer_cert_der)
        .map_err(|e| AppError::Certificate(format!("Failed to parse certificate: {}", e)))?;

    // Calculate content digest (SHA-256)
    let content_digest = calculate_sha256(content);
    tracing::info!("Content digest (sha256): {:02x?}", &content_digest);
    tracing::info!("Content length: {} bytes", content.len());

    // Build signed attributes (message-digest, content-type)
    // These are signed, not the raw content
    let signed_attrs = build_signed_attrs_raw(&content_digest, &cert)?;
    tracing::info!("Signed attrs length: {} bytes", signed_attrs.len());
    tracing::info!(
        "Signed attrs SHA256: {:02x?}",
        calculate_sha256(&signed_attrs)
    );

    let signature_value = pkcs11
        .sign_sha256_rsa_pkcs(private_key_handle, &signed_attrs)
        .map_err(|e| AppError::Signing(format!("Signing failed: {:?}", e)))?;

    tracing::info!("Signature length: {} bytes", signature_value.len());
    tracing::info!(
        "Signature first 32 bytes: {:02x?}",
        &signature_value[..std::cmp::min(32, signature_value.len())]
    );

    verify_signature_with_cert(&signed_attrs, &signature_value, &cert)?;

    let cms_data =
        build_cms_signed_data_with_attrs(content, &cert, &signed_attrs, &signature_value, false)?;

    Ok(cms_data)
}

/// Build a CAdES-BES attached signature using PKCS#11 for signing
pub fn build_cades_attached_signature(
    content: &[u8],
    signer_cert_der: &[u8],
    pkcs11: &Pkcs11Module,
    private_key_handle: ObjectHandle,
) -> Result<Vec<u8>, AppError> {
    tracing::info!(">>> build_cades_ATTACHED_signature called");
    // Load the certificate
    let cert = X509::from_der(signer_cert_der)
        .map_err(|e| AppError::Certificate(format!("Failed to parse certificate: {}", e)))?;

    // Calculate content digest (SHA-256)
    let content_digest = calculate_sha256(content);
    tracing::info!("Content digest (sha256): {:02x?}", &content_digest);
    tracing::info!("Content length: {} bytes", content.len());

    // Build signed attributes (message-digest, content-type)
    let signed_attrs = build_signed_attrs_raw(&content_digest, &cert)?;
    tracing::info!("Signed attrs length: {} bytes", signed_attrs.len());
    tracing::info!(
        "Signed attrs SHA256: {:02x?}",
        calculate_sha256(&signed_attrs)
    );

    let signature_value = pkcs11
        .sign_sha256_rsa_pkcs(private_key_handle, &signed_attrs)
        .map_err(|e| AppError::Signing(format!("Signing failed: {:?}", e)))?;

    tracing::info!("Signature length: {} bytes", signature_value.len());
    tracing::info!(
        "Signature first 32 bytes: {:02x?}",
        &signature_value[..std::cmp::min(32, signature_value.len())]
    );

    // VERIFY: Check that the signature matches the certificate
    verify_signature_with_cert(&signed_attrs, &signature_value, &cert)?;

    let cms_data =
        build_cms_signed_data_with_attrs(content, &cert, &signed_attrs, &signature_value, true)?;

    Ok(cms_data)
}

/// Verify that a signature created by the token can be validated with the certificate's public key
fn verify_signature_with_cert(data: &[u8], signature: &[u8], cert: &X509) -> Result<(), AppError> {
    let pkey = cert
        .public_key()
        .map_err(|e| AppError::Signing(format!("Failed to get public key: {}", e)))?;

    let mut verifier = openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), &pkey)
        .map_err(|e| AppError::Signing(format!("Failed to create verifier: {}", e)))?;

    verifier
        .update(data)
        .map_err(|e| AppError::Signing(format!("Failed to update verifier: {}", e)))?;

    let valid = verifier
        .verify(signature)
        .map_err(|e| AppError::Signing(format!("Failed to verify signature: {}", e)))?;

    if valid {
        tracing::info!("=== SIGNATURE VERIFICATION: PASSED ===");
        tracing::info!("The signature matches the certificate's public key!");
    } else {
        tracing::error!("=== SIGNATURE VERIFICATION: FAILED ===");
        tracing::error!("The signature does NOT match the certificate's public key!");
        tracing::error!("This means either:");
        tracing::error!("  1. The private key on the token does NOT match this certificate");
        tracing::error!(
            "  2. The certificate from the token is different from what we're embedding"
        );
        return Err(AppError::Signing(
            "Signature verification failed: private key does not match certificate".to_string(),
        ));
    }

    Ok(())
}

/// Build raw signed attributes (without the IMPLICIT [0] wrapper)
/// This returns just the SET OF attributes, which is what gets signed
fn build_signed_attrs_raw(digest: &[u8], signer_cert: &X509) -> Result<Vec<u8>, AppError> {
    let mut attrs = Vec::new();

    // content-type attribute: id-data (1.2.840.113549.1.9.3)
    let content_type_attr = build_content_type_attr()?;
    attrs.push(content_type_attr);

    // signing-time attribute (1.2.840.113549.1.9.5)
    let signing_time_attr = build_signing_time_attr()?;
    attrs.push(signing_time_attr);

    // message-digest attribute
    let digest_attr = build_message_digest_attr(digest)?;
    attrs.push(digest_attr);

    // signing-certificate-v2 attribute (1.2.840.113549.1.9.16.2.47)
    let signing_cert_attr = build_signing_certificate_v2_attr(signer_cert)?;
    attrs.push(signing_cert_attr);

    // Sort attributes for proper DER SET OF encoding (required by CMS spec)
    attrs.sort();

    let attrs_bytes: Vec<u8> = attrs.into_iter().flatten().collect();

    // Wrap in SET OF
    let mut result = Vec::new();
    result.push(0x31); // SET
    encode_length(&mut result, attrs_bytes.len())?;
    result.extend_from_slice(&attrs_bytes);

    Ok(result)
}

/// Build CMS SignedData structure with pre-computed signed attributes
fn build_cms_signed_data_with_attrs(
    content: &[u8],
    signer_cert: &X509,
    signed_attrs: &[u8],
    signature_value: &[u8],
    detached: bool,
) -> Result<Vec<u8>, AppError> {
    // Get certificate data
    let cert_der = signer_cert
        .to_der()
        .map_err(|e| AppError::Signing(format!("Failed to encode certificate: {}", e)))?;

    // Build SignerInfo with the pre-built signed attributes
    let signer_info = build_signer_info_with_attrs(signer_cert, signed_attrs, signature_value)?;

    // Build the full SignedData
    let signed_data = assemble_signed_data(content, &cert_der, &signer_info, detached)?;

    // Wrap in ContentInfo
    let content_info = wrap_content_info(&signed_data)?;

    Ok(content_info)
}

/// Build SignerInfo with pre-computed signed attributes
fn build_signer_info_with_attrs(
    cert: &X509,
    signed_attrs: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, AppError> {
    // Get issuer name and serial number
    let issuer_der = cert
        .issuer_name()
        .to_der()
        .map_err(|e| AppError::Signing(format!("Failed to encode issuer: {}", e)))?;

    let serial_der = encode_serial_number(cert.serial_number())
        .map_err(|e| AppError::Signing(format!("Failed to get serial: {}", e)))?;

    // Build SignerIdentifier (IssuerAndSerialNumber)
    let signer_id = build_issuer_and_serial(&issuer_der, &serial_der)?;

    // Build digest algorithm (SHA-256)
    let digest_algo = vec![
        0x30, 0x0d, // SEQUENCE
        0x06, 0x09, // OID
        0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, // SHA-256
        0x05, 0x00, // NULL
    ];

    // Build signature algorithm (RSA with SHA-256)
    let sig_algo = vec![
        0x30, 0x0d, // SEQUENCE
        0x06, 0x09, // OID
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, // sha256WithRSAEncryption
        0x05, 0x00, // NULL
    ];

    // signedAttrs [0] IMPLICIT replaces the SET tag
    // The signed_attrs already starts with SET (0x31), we just replace
    // the tag byte with [0] IMPLICIT (0xa0) - same length encoding
    let mut signed_attrs_wrapped = signed_attrs.to_vec();
    if !signed_attrs_wrapped.is_empty() && signed_attrs_wrapped[0] == 0x31 {
        signed_attrs_wrapped[0] = 0xa0;
    }

    // Build signature OCTET STRING
    let mut signature_octet = Vec::new();
    signature_octet.push(0x04); // OCTET STRING
    encode_length(&mut signature_octet, signature.len())?;
    signature_octet.extend_from_slice(signature);

    // Assemble SignerInfo
    let mut signer_info = Vec::new();
    signer_info.push(0x30); // SEQUENCE

    let content = [
        &vec![0x02, 0x01, 0x01][..], // version = 1
        &signer_id[..],
        &digest_algo[..],
        &signed_attrs_wrapped[..],
        &sig_algo[..],
        &signature_octet[..],
    ]
    .concat();

    encode_length(&mut signer_info, content.len())?;
    signer_info.extend_from_slice(&content);

    Ok(signer_info)
}

/// Encode an ASN.1 INTEGER from OpenSSL's Asn1IntegerRef, preserving leading zero if needed
fn encode_serial_number(serial: &openssl::asn1::Asn1IntegerRef) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let bn = serial.to_bn()?;
    let mut bytes = bn.to_vec();
    if bytes.is_empty() {
        bytes.push(0x00);
    }
    // ASN.1 INTEGER requires a leading zero byte if the high bit is set
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0x00);
    }
    let mut result = vec![0x02];
    if bytes.len() < 128 {
        result.push(bytes.len() as u8);
    } else {
        result.push(0x81);
        result.push(bytes.len() as u8);
    }
    result.extend_from_slice(&bytes);
    Ok(result)
}

/// Build IssuerAndSerialNumber
fn build_issuer_and_serial(issuer: &[u8], serial_der: &[u8]) -> Result<Vec<u8>, AppError> {
    let mut result = Vec::new();

    // Content: issuer Name + serial INTEGER (serial_der already includes tag and length)
    let content = [issuer, serial_der].concat();

    result.push(0x30); // SEQUENCE
    encode_length(&mut result, content.len())?;
    result.extend_from_slice(&content);

    Ok(result)
}

/// Build signing-time attribute (1.2.840.113549.1.9.5)
fn build_signing_time_attr() -> Result<Vec<u8>, AppError> {
    let now = chrono::Utc::now();
    let time_str = now.format("%y%m%d%H%M%SZ").to_string();
    let time_bytes = time_str.as_bytes();

    let oid = vec![
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05,
    ];

    let mut utctime = Vec::new();
    utctime.push(0x17);
    encode_length(&mut utctime, time_bytes.len())?;
    utctime.extend_from_slice(time_bytes);

    let mut value_set = Vec::new();
    value_set.push(0x31);
    encode_length(&mut value_set, utctime.len())?;
    value_set.extend_from_slice(&utctime);

    let attr_content: Vec<u8> = oid.iter().chain(value_set.iter()).copied().collect();

    let mut attr = Vec::new();
    attr.push(0x30);
    encode_length(&mut attr, attr_content.len())?;
    attr.extend_from_slice(&attr_content);

    Ok(attr)
}

/// Build signing-certificate-v2 attribute (1.2.840.113549.1.9.16.2.47)
fn build_signing_certificate_v2_attr(cert: &X509) -> Result<Vec<u8>, AppError> {
    use sha2::{Digest, Sha256};

    let cert_der = cert
        .to_der()
        .map_err(|e| AppError::Signing(format!("Failed to encode cert: {}", e)))?;

    let mut hasher = Sha256::new();
    hasher.update(&cert_der);
    let cert_hash = hasher.finalize().to_vec();

    let mut cert_hash_octet = Vec::new();
    cert_hash_octet.push(0x04);
    encode_length(&mut cert_hash_octet, cert_hash.len())?;
    cert_hash_octet.extend_from_slice(&cert_hash);

    let issuer_serial = build_issuer_serial(cert)?;

    let ess_cert_id_content = [&cert_hash_octet[..], &issuer_serial[..]].concat();
    let mut ess_cert_id = Vec::new();
    ess_cert_id.push(0x30);
    encode_length(&mut ess_cert_id, ess_cert_id_content.len())?;
    ess_cert_id.extend_from_slice(&ess_cert_id_content);

    let mut certs_seq = Vec::new();
    certs_seq.push(0x30);
    encode_length(&mut certs_seq, ess_cert_id.len())?;
    certs_seq.extend_from_slice(&ess_cert_id);

    let mut signing_cert = Vec::new();
    signing_cert.push(0x30);
    encode_length(&mut signing_cert, certs_seq.len())?;
    signing_cert.extend_from_slice(&certs_seq);

    let oid = encode_oid(&[1, 2, 840, 113549, 1, 9, 16, 2, 47]);

    let mut value_set = Vec::new();
    value_set.push(0x31);
    encode_length(&mut value_set, signing_cert.len())?;
    value_set.extend_from_slice(&signing_cert);

    let attr_content: Vec<u8> = oid.iter().chain(value_set.iter()).copied().collect();

    let mut attr = Vec::new();
    attr.push(0x30);
    encode_length(&mut attr, attr_content.len())?;
    attr.extend_from_slice(&attr_content);

    Ok(attr)
}

/// Build IssuerSerial for signing-certificate-v2
fn build_issuer_serial(cert: &X509) -> Result<Vec<u8>, AppError> {
    let issuer_der = cert
        .issuer_name()
        .to_der()
        .map_err(|e| AppError::Signing(format!("Failed to encode issuer: {}", e)))?;

    let mut general_name = Vec::new();
    general_name.push(0xa4);
    encode_length(&mut general_name, issuer_der.len())?;
    general_name.extend_from_slice(&issuer_der);

    let mut general_names = Vec::new();
    general_names.push(0x30);
    encode_length(&mut general_names, general_name.len())?;
    general_names.extend_from_slice(&general_name);

    let serial_int = encode_serial_number(cert.serial_number())
        .map_err(|e| AppError::Signing(format!("Failed to get serial: {}", e)))?;

    let content = [&general_names[..], &serial_int[..]].concat();

    let mut issuer_serial = Vec::new();
    issuer_serial.push(0x30);
    encode_length(&mut issuer_serial, content.len())?;
    issuer_serial.extend_from_slice(&content);

    Ok(issuer_serial)
}

/// Encode OID components to DER
fn encode_oid(components: &[u64]) -> Vec<u8> {
    if components.len() < 2 {
        return Vec::new();
    }

    let mut encoded = Vec::new();
    encoded.push((components[0] as u8 * 40) + components[1] as u8);

    for &comp in &components[2..] {
        if comp == 0 {
            encoded.push(0x00);
        } else {
            let mut bytes = Vec::new();
            let mut val = comp;
            bytes.push((val & 0x7F) as u8);
            val >>= 7;
            while val > 0 {
                bytes.push((val & 0x7F) as u8 | 0x80);
                val >>= 7;
            }
            bytes.reverse();
            encoded.extend_from_slice(&bytes);
        }
    }

    let mut result = Vec::new();
    result.push(0x06);
    if encoded.len() < 128 {
        result.push(encoded.len() as u8);
    } else if encoded.len() < 256 {
        result.push(0x81);
        result.push(encoded.len() as u8);
    } else {
        result.push(0x82);
        result.push((encoded.len() >> 8) as u8);
        result.push((encoded.len() & 0xFF) as u8);
    }
    result.extend_from_slice(&encoded);
    result
}

fn build_content_type_attr() -> Result<Vec<u8>, AppError> {
    // Attribute ::= SEQUENCE {
    //     attrType OBJECT IDENTIFIER,
    //     attrValues SET OF AttributeValue
    // }

    // contentType OID: 1.2.840.113549.1.9.3
    let oid = vec![
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03,
    ];

    // id-data OID: 1.2.840.113549.1.7.1
    let value = vec![
        0x31, 0x0b, // SET
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
    ];

    let content = [oid, value].concat();

    let mut result = Vec::new();
    result.push(0x30); // SEQUENCE
    encode_length(&mut result, content.len())?;
    result.extend_from_slice(&content);

    Ok(result)
}

/// Build message-digest attribute
fn build_message_digest_attr(digest: &[u8]) -> Result<Vec<u8>, AppError> {
    // messageDigest OID: 1.2.840.113549.1.9.4
    let oid = vec![
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04,
    ];

    // digest as OCTET STRING in a SET
    let mut value = Vec::new();
    value.push(0x31); // SET
    let mut inner = Vec::new();
    inner.push(0x04); // OCTET STRING
    encode_length(&mut inner, digest.len())?;
    inner.extend_from_slice(digest);
    encode_length(&mut value, inner.len())?;
    value.extend_from_slice(&inner);

    let content = [oid, value].concat();

    let mut result = Vec::new();
    result.push(0x30); // SEQUENCE
    encode_length(&mut result, content.len())?;
    result.extend_from_slice(&content);

    Ok(result)
}

/// Assemble SignedData
fn assemble_signed_data(
    content: &[u8],
    cert_der: &[u8],
    signer_info: &[u8],
    detached: bool,
) -> Result<Vec<u8>, AppError> {
    let mut signed_data = Vec::new();

    // version
    let version = vec![0x02, 0x01, 0x01]; // INTEGER 1

    // digestAlgorithms (SET of AlgorithmIdentifier)
    let digest_algos = vec![
        0x31, 0x0d, // SET
        0x30, 0x0b, // SEQUENCE
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, // SHA-256
    ];

    // contentInfo
    let content_info = if detached {
        // id-data with no content
        vec![
            0x30, 0x0b, // SEQUENCE
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, // id-data
        ]
    } else {
        // id-data with content
        let mut ci = Vec::new();
        ci.push(0x30); // SEQUENCE
        let mut inner = vec![
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, // id-data
            0xa0, // [0] EXPLICIT (content)
        ];
        let mut octet = Vec::new();
        octet.push(0x04); // OCTET STRING
        encode_length(&mut octet, content.len())?;
        octet.extend_from_slice(content);
        encode_length(&mut inner, octet.len())?;
        inner.extend_from_slice(&octet);
        encode_length(&mut ci, inner.len())?;
        ci.extend_from_slice(&inner);
        ci
    };

    // certificates [0] EXPLICIT
    let mut certs = Vec::new();
    certs.push(0xa0); // [0] CONSTRUCTED
    let mut cert_content = Vec::new();
    cert_content.extend_from_slice(cert_der);
    encode_length(&mut certs, cert_content.len())?;
    certs.extend_from_slice(&cert_content);

    // signerInfos (SET of SignerInfo)
    let mut signer_infos = Vec::new();
    signer_infos.push(0x31); // SET
    encode_length(&mut signer_infos, signer_info.len())?;
    signer_infos.extend_from_slice(signer_info);

    // Assemble content
    let content = [
        &version[..],
        &digest_algos[..],
        &content_info[..],
        &certs[..],
        &signer_infos[..],
    ]
    .concat();

    signed_data.push(0x30); // SEQUENCE
    encode_length(&mut signed_data, content.len())?;
    signed_data.extend_from_slice(&content);

    Ok(signed_data)
}

/// Wrap in ContentInfo
fn wrap_content_info(signed_data: &[u8]) -> Result<Vec<u8>, AppError> {
    let mut result = Vec::new();

    // contentType: signedData (1.2.840.113549.1.7.2)
    let content_type = vec![
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
    ];

    // content [0] EXPLICIT
    let mut content = Vec::new();
    content.push(0xa0); // [0] CONSTRUCTED
    encode_length(&mut content, signed_data.len())?;
    content.extend_from_slice(signed_data);

    let inner = [content_type, content].concat();

    result.push(0x30); // SEQUENCE
    encode_length(&mut result, inner.len())?;
    result.extend_from_slice(&inner);

    Ok(result)
}

/// Encode ASN.1 length
fn encode_length(out: &mut Vec<u8>, len: usize) -> Result<(), AppError> {
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else if len < 65536 {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    } else if len < 16777216 {
        out.push(0x83);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    } else if len < 4294967296 {
        out.push(0x84);
        out.push((len >> 24) as u8);
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    } else {
        return Err(AppError::Signing("Length too large".to_string()));
    }
    Ok(())
}

/// Calculate SHA-256 digest
fn calculate_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_sha256() {
        let data = b"test";
        let hash = calculate_sha256(data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_encode_length() {
        let mut v = Vec::new();
        encode_length(&mut v, 100).unwrap();
        assert_eq!(v, vec![0x64]);

        v.clear();
        encode_length(&mut v, 200).unwrap();
        assert_eq!(v, vec![0x81, 0xC8]);
    }
}
