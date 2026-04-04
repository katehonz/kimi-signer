use crate::crypto::pkcs11::Pkcs11Module;
use crate::models::AppError;
use cryptoki::object::ObjectHandle;
use lopdf::Dictionary as LoDictionary;
use lopdf::Document;
use lopdf::Object as LoObject;
use lopdf::ObjectId;
use lopdf::Stream as LoStream;
use lopdf::StringFormat;
use openssl::x509::X509;
use sha2::{Digest, Sha256};

const SIGNATURE_BYTE_RANGE_PLACEHOLDER: i64 = 9999999999i64;
const SIGNATURE_HEX_LEN: usize = 16384;
const SIGNATURE_BIN_LEN: usize = SIGNATURE_HEX_LEN / 2;

pub fn sign_pdf_pades(
    pdf_bytes: &[u8],
    signer_cert_der: &[u8],
    pkcs11: &Pkcs11Module,
    private_key_handle: ObjectHandle,
    signer_name: &str,
) -> Result<Vec<u8>, AppError> {
    let mut doc = Document::load_mem(pdf_bytes)
        .map_err(|e| AppError::Signing(format!("Failed to load PDF: {}", e)))?;

    let signing_time = chrono::Utc::now();
    let date_str = format_pdf_date(&signing_time);

    let placeholder_bytes = vec![0u8; SIGNATURE_BIN_LEN];

    let sig_dict = LoDictionary::from_iter(vec![
        ("Type", LoObject::Name(b"Sig".to_vec())),
        ("Filter", LoObject::Name(b"Adobe.PPKLite".to_vec())),
        ("SubFilter", LoObject::Name(b"ETSI.CAdES.detached".to_vec())),
        (
            "ByteRange",
            LoObject::Array(vec![
                LoObject::Integer(0),
                LoObject::Integer(SIGNATURE_BYTE_RANGE_PLACEHOLDER),
                LoObject::Integer(SIGNATURE_BYTE_RANGE_PLACEHOLDER),
                LoObject::Integer(0),
            ]),
        ),
        (
            "Contents",
            LoObject::String(placeholder_bytes, StringFormat::Hexadecimal),
        ),
        (
            "M",
            LoObject::String(date_str.into_bytes(), StringFormat::Literal),
        ),
        (
            "Prop_Build",
            LoObject::Dictionary(LoDictionary::from_iter(vec![(
                "Filter",
                LoObject::Dictionary(LoDictionary::from_iter(vec![(
                    "Name",
                    LoObject::Name(b"Adobe.PPKLite".to_vec()),
                )])),
            )])),
        ),
        ("Prop_AuthType", LoObject::Name(b"PKCS7".to_vec())),
    ]);

    let appearance_stream = create_stamp_appearance(signer_name, &signing_time);

    let stamp_x: f32 = 20.0;
    let stamp_y: f32 = 20.0;
    let stamp_w: f32 = 180.0;
    let stamp_h: f32 = 60.0;

    let sig_field_dict = LoDictionary::from_iter(vec![
        ("Type", LoObject::Name(b"Annot".to_vec())),
        ("Subtype", LoObject::Name(b"Widget".to_vec())),
        ("FT", LoObject::Name(b"Sig".to_vec())),
        (
            "T",
            LoObject::String(b"Signature1".to_vec(), StringFormat::Literal),
        ),
        ("V", LoObject::Dictionary(sig_dict)),
        (
            "Rect",
            LoObject::Array(vec![
                LoObject::Real(stamp_x),
                LoObject::Real(stamp_y),
                LoObject::Real(stamp_x + stamp_w),
                LoObject::Real(stamp_y + stamp_h),
            ]),
        ),
        ("P", LoObject::Reference(get_first_page_id(&doc))),
        (
            "AP",
            LoObject::Dictionary(LoDictionary::from_iter(vec![(
                "N",
                LoObject::Stream(appearance_stream),
            )])),
        ),
        ("F", LoObject::Integer(132)),
    ]);

    let sig_field_id = doc.add_object(LoObject::Dictionary(sig_field_dict));
    ensure_acroform(&mut doc, sig_field_id);
    add_annot_to_first_page(&mut doc, sig_field_id)?;

    let mut output_buf: Vec<u8> = Vec::new();
    doc.save_to(&mut output_buf)
        .map_err(|e| AppError::Signing(format!("Failed to save PDF: {}", e)))?;

    let (lt_pos, gt_pos) = find_contents_hex_positions(&output_buf)?;

    let byte_range = [
        0i64,
        lt_pos as i64,
        (gt_pos + 1) as i64,
        (output_buf.len() as i64) - (gt_pos as i64) - 1,
    ];

    replace_byte_range_placeholder(&mut output_buf, &byte_range)?;

    let mut data_to_sign = Vec::with_capacity(output_buf.len());
    data_to_sign.extend_from_slice(&output_buf[..lt_pos]);
    data_to_sign.extend_from_slice(&output_buf[gt_pos + 1..]);

    let cms_signature =
        build_cms_for_pades(&data_to_sign, signer_cert_der, pkcs11, private_key_handle)?;

    let sig_hex = bytes_to_hex(&cms_signature);
    if sig_hex.len() > SIGNATURE_HEX_LEN {
        return Err(AppError::Signing(format!(
            "CMS signature too large: {} hex chars, max {}",
            sig_hex.len(),
            SIGNATURE_HEX_LEN
        )));
    }

    let padded_hex = format!("{:0<width$}", sig_hex, width = SIGNATURE_HEX_LEN);
    output_buf[lt_pos + 1..gt_pos].copy_from_slice(padded_hex.as_bytes());

    Ok(output_buf)
}

fn find_contents_hex_positions(output: &[u8]) -> Result<(usize, usize), AppError> {
    let zeros_str: String = "0".repeat(SIGNATURE_HEX_LEN);
    let pattern = format!("<{}>", zeros_str);

    let pattern_bytes = pattern.as_bytes();
    let pos = find_subsequence(output, pattern_bytes).ok_or_else(|| {
        AppError::Signing("Failed to locate signature hex placeholder in PDF output".to_string())
    })?;

    let lt_pos = pos;
    let gt_pos = pos + pattern_bytes.len() - 1;
    Ok((lt_pos, gt_pos))
}

fn replace_byte_range_placeholder(output: &mut [u8], byte_range: &[i64]) -> Result<(), AppError> {
    let placeholder = format!(
        "[0 {} {} 0]",
        SIGNATURE_BYTE_RANGE_PLACEHOLDER, SIGNATURE_BYTE_RANGE_PLACEHOLDER
    );
    let placeholder_bytes = placeholder.as_bytes();

    let pos = find_subsequence(output, placeholder_bytes)
        .ok_or_else(|| AppError::Signing("Failed to locate ByteRange placeholder".to_string()))?;

    let replacement = format!(
        "[{} {} {} {}]",
        byte_range[0], byte_range[1], byte_range[2], byte_range[3]
    );

    let padded = format!("{:<width$}", replacement, width = placeholder_bytes.len());

    output[pos..pos + placeholder_bytes.len()].copy_from_slice(padded.as_bytes());

    Ok(())
}

fn build_cms_for_pades(
    content: &[u8],
    signer_cert_der: &[u8],
    pkcs11: &Pkcs11Module,
    private_key_handle: ObjectHandle,
) -> Result<Vec<u8>, AppError> {
    let cert = X509::from_der(signer_cert_der)
        .map_err(|e| AppError::Certificate(format!("Failed to parse certificate: {}", e)))?;

    let content_digest = calculate_sha256(content);
    let signed_attrs = build_pades_signed_attrs(&content_digest, &cert)?;

    let signature_value = pkcs11
        .sign_sha256_rsa_pkcs(private_key_handle, &signed_attrs)
        .map_err(|e| AppError::Signing(format!("Signing failed: {:?}", e)))?;

    let cms_data = build_pades_cms_signed_data(&cert, &signed_attrs, &signature_value)?;
    Ok(cms_data)
}

fn build_pades_signed_attrs(digest: &[u8], signer_cert: &X509) -> Result<Vec<u8>, AppError> {
    let mut attrs = Vec::new();
    attrs.push(build_content_type_attr_pades()?);
    attrs.push(build_signing_time_attr_pades()?);
    attrs.push(build_message_digest_attr_pades(digest)?);
    attrs.push(build_signing_certificate_v2_attr_pades(signer_cert)?);
    attrs.sort();

    let attrs_bytes: Vec<u8> = attrs.into_iter().flatten().collect();
    let mut result = Vec::new();
    result.push(0x31);
    encode_len(&mut result, attrs_bytes.len())?;
    result.extend_from_slice(&attrs_bytes);
    Ok(result)
}

fn build_pades_cms_signed_data(
    signer_cert: &X509,
    signed_attrs: &[u8],
    signature_value: &[u8],
) -> Result<Vec<u8>, AppError> {
    let cert_der = signer_cert
        .to_der()
        .map_err(|e| AppError::Signing(format!("Failed to encode certificate: {}", e)))?;
    let signer_info = build_pades_signer_info(signer_cert, signed_attrs, signature_value)?;
    let signed_data = assemble_pades_signed_data(&cert_der, &signer_info)?;
    wrap_content_info(&signed_data)
}

fn build_pades_signer_info(
    cert: &X509,
    signed_attrs: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, AppError> {
    let issuer_der = cert
        .issuer_name()
        .to_der()
        .map_err(|e| AppError::Signing(format!("Failed to encode issuer: {}", e)))?;
    let serial_der = encode_serial(cert.serial_number())
        .map_err(|e| AppError::Signing(format!("Failed to get serial: {}", e)))?;
    let signer_id = build_issuer_and_serial(&issuer_der, &serial_der)?;

    let digest_algo = vec![
        0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
    ];
    let sig_algo = vec![
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
    ];

    let mut signed_attrs_wrapped = signed_attrs.to_vec();
    if !signed_attrs_wrapped.is_empty() && signed_attrs_wrapped[0] == 0x31 {
        signed_attrs_wrapped[0] = 0xa0;
    }

    let mut signature_octet = Vec::new();
    signature_octet.push(0x04);
    encode_len(&mut signature_octet, signature.len())?;
    signature_octet.extend_from_slice(signature);

    let mut signer_info = Vec::new();
    signer_info.push(0x30);
    let content = [
        &vec![0x02, 0x01, 0x01][..],
        &signer_id[..],
        &digest_algo[..],
        &signed_attrs_wrapped[..],
        &sig_algo[..],
        &signature_octet[..],
    ]
    .concat();
    encode_len(&mut signer_info, content.len())?;
    signer_info.extend_from_slice(&content);
    Ok(signer_info)
}

fn assemble_pades_signed_data(cert_der: &[u8], signer_info: &[u8]) -> Result<Vec<u8>, AppError> {
    let version = vec![0x02, 0x01, 0x01];
    let digest_algos = vec![
        0x31, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    ];
    let encap_content_info = vec![
        0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
    ];

    let mut certs = Vec::new();
    certs.push(0xa0);
    encode_len(&mut certs, cert_der.len())?;
    certs.extend_from_slice(cert_der);

    let mut signer_infos = Vec::new();
    signer_infos.push(0x31);
    encode_len(&mut signer_infos, signer_info.len())?;
    signer_infos.extend_from_slice(signer_info);

    let sd_content = [
        &version[..],
        &digest_algos[..],
        &encap_content_info[..],
        &certs[..],
        &signer_infos[..],
    ]
    .concat();

    let mut signed_data = Vec::new();
    signed_data.push(0x30);
    encode_len(&mut signed_data, sd_content.len())?;
    signed_data.extend_from_slice(&sd_content);
    Ok(signed_data)
}

fn wrap_content_info(signed_data: &[u8]) -> Result<Vec<u8>, AppError> {
    let content_type_oid = vec![
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
    ];
    let mut explicit = Vec::new();
    explicit.push(0xa0);
    encode_len(&mut explicit, signed_data.len())?;
    explicit.extend_from_slice(signed_data);

    let inner = [content_type_oid, explicit].concat();
    let mut result = Vec::new();
    result.push(0x30);
    encode_len(&mut result, inner.len())?;
    result.extend_from_slice(&inner);
    Ok(result)
}

// ── Stamp appearance ──

fn create_stamp_appearance(
    signer_name: &str,
    signing_time: &chrono::DateTime<chrono::Utc>,
) -> LoStream {
    let date_str = signing_time.format("%d.%m.%Y %H:%M").to_string();
    let content_stream = format!(
        "q\n\
         0.95 0.95 0.95 rg\n\
         0 0 180 60 re f\n\
         0.7 0.7 0.7 RG 0.5 w\n\
         0 0 180 60 re S\n\
         0.1 0.5 0.1 rg\n\
         BT\n\
         /F1 7 Tf 8 45 Td (Digitally Signed) Tj\n\
         0 0 0 rg\n\
         /F1 6 Tf 8 32 Td ({}) Tj\n\
         /F1 5 Tf 8 20 Td ({}) Tj\n\
         ET Q\n",
        escape_pdf_string(signer_name),
        escape_pdf_string(&date_str)
    );

    let resources = LoDictionary::from_iter(vec![(
        "Font",
        LoObject::Dictionary(LoDictionary::from_iter(vec![(
            "F1",
            LoObject::Dictionary(LoDictionary::from_iter(vec![
                ("Type", LoObject::Name(b"Font".to_vec())),
                ("Subtype", LoObject::Name(b"Type1".to_vec())),
                ("BaseFont", LoObject::Name(b"Helvetica".to_vec())),
                ("Encoding", LoObject::Name(b"WinAnsiEncoding".to_vec())),
            ])),
        )])),
    )]);

    let dict = LoDictionary::from_iter(vec![
        ("Type", LoObject::Name(b"XObject".to_vec())),
        ("Subtype", LoObject::Name(b"Form".to_vec())),
        (
            "BBox",
            LoObject::Array(vec![
                LoObject::Real(0.0),
                LoObject::Real(0.0),
                LoObject::Real(180.0),
                LoObject::Real(60.0),
            ]),
        ),
        ("Resources", LoObject::Dictionary(resources)),
    ]);

    let mut stream = LoStream::new(dict, content_stream.into_bytes());
    let _ = stream.compress();
    stream
}

fn escape_pdf_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('(', "\\(")
        .replace(')', "\\)")
}

// ── PDF structure helpers ──

fn ensure_acroform(doc: &mut Document, sig_field_id: ObjectId) {
    if let Ok(catalog) = doc.catalog_mut() {
        let acroform = catalog.get(b"AcroForm").cloned();
        match acroform {
            Ok(LoObject::Dictionary(mut af_dict)) => {
                let fields = af_dict.get(b"Fields").cloned();
                match fields {
                    Ok(LoObject::Array(mut arr)) => {
                        arr.push(LoObject::Reference(sig_field_id));
                        af_dict.set("Fields", LoObject::Array(arr));
                    }
                    _ => {
                        af_dict.set(
                            "Fields",
                            LoObject::Array(vec![LoObject::Reference(sig_field_id)]),
                        );
                    }
                }
                af_dict.set("SigFlags", LoObject::Integer(3));
                catalog.set("AcroForm", LoObject::Dictionary(af_dict));
            }
            _ => {
                let acroform_dict = LoDictionary::from_iter(vec![
                    (
                        "Fields",
                        LoObject::Array(vec![LoObject::Reference(sig_field_id)]),
                    ),
                    ("SigFlags", LoObject::Integer(3)),
                    ("NeedAppearances", LoObject::Boolean(false)),
                ]);
                catalog.set("AcroForm", LoObject::Dictionary(acroform_dict));
            }
        }
    }
}

fn add_annot_to_first_page(doc: &mut Document, sig_field_id: ObjectId) -> Result<(), AppError> {
    let pages = doc.get_pages();
    let first_page_id = *pages
        .get(&1)
        .ok_or_else(|| AppError::Signing("No pages in PDF".to_string()))?;

    if let Ok(LoObject::Dictionary(page_dict)) = doc.get_object_mut(first_page_id) {
        let annots = page_dict.get(b"Annots").cloned();
        match annots {
            Ok(LoObject::Array(mut arr)) => {
                arr.push(LoObject::Reference(sig_field_id));
                page_dict.set("Annots", LoObject::Array(arr));
            }
            _ => {
                page_dict.set(
                    "Annots",
                    LoObject::Array(vec![LoObject::Reference(sig_field_id)]),
                );
            }
        }
    }
    Ok(())
}

fn get_first_page_id(doc: &Document) -> ObjectId {
    doc.get_pages().get(&1).copied().unwrap_or((0u32, 0u16))
}

// ── Binary search helpers ──

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{:02X}", b));
    }
    s
}

fn format_pdf_date(dt: &chrono::DateTime<chrono::Utc>) -> String {
    format!("D:{}", dt.format("%Y%m%d%H%M%S+00'00'"))
}

fn calculate_sha256(data: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}

// ── ASN.1 / DER helpers ──

fn encode_len(out: &mut Vec<u8>, len: usize) -> Result<(), AppError> {
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
    } else {
        return Err(AppError::Signing("ASN.1 length too large".to_string()));
    }
    Ok(())
}

fn encode_serial(
    serial: &openssl::asn1::Asn1IntegerRef,
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let bn = serial.to_bn()?;
    let mut bytes = bn.to_vec();
    if bytes.is_empty() {
        bytes.push(0x00);
    }
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

fn build_issuer_and_serial(issuer: &[u8], serial_der: &[u8]) -> Result<Vec<u8>, AppError> {
    let content = [issuer, serial_der].concat();
    let mut r = Vec::new();
    r.push(0x30);
    encode_len(&mut r, content.len())?;
    r.extend_from_slice(&content);
    Ok(r)
}

fn build_content_type_attr_pades() -> Result<Vec<u8>, AppError> {
    let oid = vec![
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03,
    ];
    let val = vec![
        0x31, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
    ];
    let c = [oid, val].concat();
    let mut r = Vec::new();
    r.push(0x30);
    encode_len(&mut r, c.len())?;
    r.extend_from_slice(&c);
    Ok(r)
}

fn build_signing_time_attr_pades() -> Result<Vec<u8>, AppError> {
    let now = chrono::Utc::now();
    let ts = now.format("%y%m%d%H%M%SZ").to_string();
    let tb = ts.as_bytes();

    let oid = vec![
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05,
    ];
    let mut utc = Vec::new();
    utc.push(0x17);
    encode_len(&mut utc, tb.len())?;
    utc.extend_from_slice(tb);

    let mut vs = Vec::new();
    vs.push(0x31);
    encode_len(&mut vs, utc.len())?;
    vs.extend_from_slice(&utc);

    let ac: Vec<u8> = oid.iter().chain(vs.iter()).copied().collect();
    let mut a = Vec::new();
    a.push(0x30);
    encode_len(&mut a, ac.len())?;
    a.extend_from_slice(&ac);
    Ok(a)
}

fn build_message_digest_attr_pades(digest: &[u8]) -> Result<Vec<u8>, AppError> {
    let oid = vec![
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04,
    ];
    let mut inner = Vec::new();
    inner.push(0x04);
    encode_len(&mut inner, digest.len())?;
    inner.extend_from_slice(digest);

    let mut vs = Vec::new();
    vs.push(0x31);
    encode_len(&mut vs, inner.len())?;
    vs.extend_from_slice(&inner);

    let c = [oid, vs].concat();
    let mut r = Vec::new();
    r.push(0x30);
    encode_len(&mut r, c.len())?;
    r.extend_from_slice(&c);
    Ok(r)
}

fn build_signing_certificate_v2_attr_pades(cert: &X509) -> Result<Vec<u8>, AppError> {
    let cert_der = cert
        .to_der()
        .map_err(|e| AppError::Signing(format!("Failed to encode cert: {}", e)))?;
    let cert_hash = calculate_sha256(&cert_der);

    let mut hash_oct = Vec::new();
    hash_oct.push(0x04);
    encode_len(&mut hash_oct, cert_hash.len())?;
    hash_oct.extend_from_slice(&cert_hash);

    let issuer_serial = build_issuer_serial_pades(cert)?;
    let ess_content = [&hash_oct[..], &issuer_serial[..]].concat();

    let mut ess_id = Vec::new();
    ess_id.push(0x30);
    encode_len(&mut ess_id, ess_content.len())?;
    ess_id.extend_from_slice(&ess_content);

    let mut certs_seq = Vec::new();
    certs_seq.push(0x30);
    encode_len(&mut certs_seq, ess_id.len())?;
    certs_seq.extend_from_slice(&ess_id);

    let mut signing_cert = Vec::new();
    signing_cert.push(0x30);
    encode_len(&mut signing_cert, certs_seq.len())?;
    signing_cert.extend_from_slice(&certs_seq);

    let oid = encode_oid(&[1, 2, 840, 113549, 1, 9, 16, 2, 47]);
    let mut vs = Vec::new();
    vs.push(0x31);
    encode_len(&mut vs, signing_cert.len())?;
    vs.extend_from_slice(&signing_cert);

    let ac: Vec<u8> = oid.iter().chain(vs.iter()).copied().collect();
    let mut a = Vec::new();
    a.push(0x30);
    encode_len(&mut a, ac.len())?;
    a.extend_from_slice(&ac);
    Ok(a)
}

fn build_issuer_serial_pades(cert: &X509) -> Result<Vec<u8>, AppError> {
    let issuer_der = cert
        .issuer_name()
        .to_der()
        .map_err(|e| AppError::Signing(format!("Failed to encode issuer: {}", e)))?;

    let mut gn = Vec::new();
    gn.push(0xa4);
    encode_len(&mut gn, issuer_der.len())?;
    gn.extend_from_slice(&issuer_der);

    let mut gns = Vec::new();
    gns.push(0x30);
    encode_len(&mut gns, gn.len())?;
    gns.extend_from_slice(&gn);

    let ser = encode_serial(cert.serial_number())
        .map_err(|e| AppError::Signing(format!("Failed to get serial: {}", e)))?;

    let c = [&gns[..], &ser[..]].concat();
    let mut r = Vec::new();
    r.push(0x30);
    encode_len(&mut r, c.len())?;
    r.extend_from_slice(&c);
    Ok(r)
}

fn encode_oid(components: &[u64]) -> Vec<u8> {
    if components.len() < 2 {
        return Vec::new();
    }
    let mut enc = Vec::new();
    enc.push((components[0] as u8 * 40) + components[1] as u8);
    for &comp in &components[2..] {
        if comp == 0 {
            enc.push(0x00);
        } else {
            let mut bs = Vec::new();
            let mut v = comp;
            bs.push((v & 0x7F) as u8);
            v >>= 7;
            while v > 0 {
                bs.push((v & 0x7F) as u8 | 0x80);
                v >>= 7;
            }
            bs.reverse();
            enc.extend_from_slice(&bs);
        }
    }
    let mut r = Vec::new();
    r.push(0x06);
    if enc.len() < 128 {
        r.push(enc.len() as u8);
    } else if enc.len() < 256 {
        r.push(0x81);
        r.push(enc.len() as u8);
    } else {
        r.push(0x82);
        r.push((enc.len() >> 8) as u8);
        r.push((enc.len() & 0xFF) as u8);
    }
    r.extend_from_slice(&enc);
    r
}
