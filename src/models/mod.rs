use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureType {
    /// Attached/Enveloping - подписът е вграден в документа (.p7m)
    Attached,
    /// Detached - подписът е в отделен файл (.p7s)
    Detached,
}

impl SignatureType {
    pub fn extension(&self) -> &'static str {
        match self {
            SignatureType::Attached => ".p7m",
            SignatureType::Detached => ".p7s",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            SignatureType::Attached => "Attached/Enveloping (.p7m) - подписът е вграден",
            SignatureType::Detached => "Detached (.p7s) - подписът е отделен",
        }
    }
}

impl Default for SignatureType {
    fn default() -> Self {
        SignatureType::Attached
    }
}

#[derive(Debug, Clone)]
pub struct SignRequest {
    pub file_path: PathBuf,
    pub signature_type: SignatureType,
    pub output_path: Option<PathBuf>,
    pub certificate: CertificateInfo,
    pub pin: String,
}

#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub valid_from: chrono::DateTime<chrono::Utc>,
    pub valid_to: chrono::DateTime<chrono::Utc>,
    pub thumbprint: String,
    pub has_private_key: bool,
}

impl CertificateInfo {
    pub fn is_valid(&self) -> bool {
        let now = chrono::Utc::now();
        self.valid_from <= now && now <= self.valid_to
    }

    pub fn validity_status(&self) -> CertificateValidity {
        let now = chrono::Utc::now();
        if now < self.valid_from {
            CertificateValidity::NotYetValid
        } else if now > self.valid_to {
            CertificateValidity::Expired
        } else {
            CertificateValidity::Valid
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateValidity {
    Valid,
    NotYetValid,
    Expired,
}

#[derive(Debug, Default)]
pub struct AppState {
    pub pkcs11_modules: Vec<String>,
    pub trusted_certificates: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct SignatureResult {
    pub success: bool,
    pub output_path: PathBuf,
    pub message: String,
}

#[derive(Debug, Clone)]
pub enum AppError {
    Pkcs11(String),
    Certificate(String),
    Signing(String),
    Io(String),
    InvalidPin,
    NoCertificateSelected,
    NoTokenDetected,
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Pkcs11(msg) => write!(f, "PKCS#11 грешка: {}", msg),
            AppError::Certificate(msg) => write!(f, "Грешка със сертификат: {}", msg),
            AppError::Signing(msg) => write!(f, "Грешка при подписване: {}", msg),
            AppError::Io(msg) => write!(f, "I/O грешка: {}", msg),
            AppError::InvalidPin => write!(f, "Невалиден ПИН код"),
            AppError::NoCertificateSelected => write!(f, "Не е избран сертификат"),
            AppError::NoTokenDetected => write!(f, "Не е открит токен/смарт карта"),
        }
    }
}

impl std::error::Error for AppError {}
