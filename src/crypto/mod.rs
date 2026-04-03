use crate::models::{AppError, SignatureType, SignRequest, SignatureResult, CertificateInfo};
use std::path::PathBuf;

pub mod pkcs11;
pub mod cades;
pub mod certificate;
pub mod cms_builder;

pub use pkcs11::{Pkcs11Module, TokenCertificate};

/// PKCS#11 Module information
#[derive(Debug, Clone)]
pub struct Pkcs11ModuleInfo {
    pub name: String,
    pub path: String,
}

/// Main signing service
pub struct SigningService {
    pkcs11: Option<Pkcs11Module>,
    current_module_path: Option<String>,
}

impl SigningService {
    pub fn new() -> Self {
        Self { 
            pkcs11: None,
            current_module_path: None,
        }
    }

    /// Initialize PKCS#11 module with a library path
    pub fn initialize_pkcs11(&mut self, library_path: &str) -> Result<(), AppError> {
        let mut module = Pkcs11Module::new(library_path)
            .map_err(|e| AppError::Pkcs11(e.to_string()))?;
        
        // Open session
        module.open_session()
            .map_err(|e| AppError::Pkcs11(format!("Failed to open session: {}", e)))?;
        
        self.pkcs11 = Some(module);
        self.current_module_path = Some(library_path.to_string());
        Ok(())
    }

    /// Get currently loaded module path
    pub fn get_current_module(&self) -> Option<&str> {
        self.current_module_path.as_deref()
    }

    /// Detect available PKCS#11 modules on the system
    pub fn detect_modules() -> Vec<Pkcs11ModuleInfo> {
        let mut modules = Vec::new();

        // Common Bulgarian eID provider paths
        #[cfg(target_os = "windows")]
        let common_paths = [
            ("B-Trust", r"C:\Windows\System32\btrustpkcs11.dll"),
            ("B-Trust (SysWOW64)", r"C:\Windows\SysWOW64\btrustpkcs11.dll"),
            ("StampIT", r"C:\Windows\System32\STAMPP11.dll"),
            ("StampIT (SysWOW64)", r"C:\Windows\SysWOW64\STAMPP11.dll"),
            ("InfoNotary", r"C:\Windows\System32\innp11.dll"),
            ("InfoNotary (SysWOW64)", r"C:\Windows\SysWOW64\innp11.dll"),
            ("Bit4ID", r"C:\Windows\System32\bit4ipki.dll"),
            ("Bit4ID (SysWOW64)", r"C:\Windows\SysWOW64\bit4ipki.dll"),
        ];

        #[cfg(target_os = "linux")]
        let common_paths = [
            ("B-Trust", "/usr/lib/libbtrustpkcs11.so"),
            ("B-Trust (x64)", "/usr/lib64/libbtrustpkcs11.so"),
            ("B-Trust (x86)", "/usr/lib/x86_64-linux-gnu/libbtrustpkcs11.so"),
            ("StampIT", "/usr/lib/libstampp11.so"),
            ("StampIT (x64)", "/usr/lib64/libstampp11.so"),
            ("InfoNotary", "/usr/lib/libinnp11.so"),
            ("InfoNotary (x64)", "/usr/lib64/libinnp11.so"),
            ("Bit4ID", "/usr/lib/libbit4ipki.so"),
            ("Bit4ID (x64)", "/usr/lib64/libbit4ipki.so"),
        ];

        #[cfg(target_os = "macos")]
        let common_paths = [
            ("B-Trust", "/usr/local/lib/libbtrustpkcs11.dylib"),
            ("StampIT", "/usr/local/lib/libstampp11.dylib"),
            ("InfoNotary", "/usr/local/lib/libinnp11.dylib"),
        ];

        for (name, path) in common_paths.iter() {
            if std::path::Path::new(path).exists() {
                modules.push(Pkcs11ModuleInfo {
                    name: name.to_string(),
                    path: path.to_string(),
                });
            }
        }

        modules
    }

    /// Check if PKCS#11 is initialized
    pub fn is_initialized(&self) -> bool {
        self.pkcs11.is_some()
    }

    /// Get reference to PKCS#11 module
    pub fn get_pkcs11_module(&self) -> Option<&Pkcs11Module> {
        self.pkcs11.as_ref()
    }

    /// Login to the token
    pub fn login(&self, pin: &str) -> Result<(), AppError> {
        if let Some(ref pkcs11) = self.pkcs11 {
            pkcs11.login(pin)
        } else {
            Err(AppError::Pkcs11("PKCS#11 module not initialized".to_string()))
        }
    }

    /// Logout from the token
    pub fn logout(&self) -> Result<(), AppError> {
        if let Some(ref pkcs11) = self.pkcs11 {
            pkcs11.logout()
        } else {
            Ok(())
        }
    }

    /// Get certificates from the token
    pub fn get_certificates(&self) -> Result<Vec<TokenCertificate>, AppError> {
        if let Some(ref pkcs11) = self.pkcs11 {
            pkcs11.enumerate_certificates()
        } else {
            Err(AppError::Pkcs11("PKCS#11 module not initialized".to_string()))
        }
    }

    /// Sign a document using the token
    pub fn sign_document(
        &self,
        request: &SignRequest,
        token_cert: &TokenCertificate,
    ) -> Result<SignatureResult, AppError> {
        // Read the file content
        let content = std::fs::read(&request.file_path)
            .map_err(|e| AppError::Io(format!("Failed to read file: {}", e)))?;

        // Determine output path
        let output_path = request.output_path.clone().unwrap_or_else(|| {
            let stem = request.file_path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("signed");
            let parent = request.file_path.parent()
                .unwrap_or(std::path::Path::new("."));
            parent.join(format!("{}{}", stem, request.signature_type.extension()))
        });

        // For now, we'll use software signing for testing
        // In production, this would use PKCS#11 for signing
        let signature_data = if let Some(ref pkcs11) = self.pkcs11 {
            // Sign using the token
            self.sign_with_token(&content, token_cert, request.signature_type, pkcs11)?
        } else {
            // Fallback: software signing (for testing only)
            tracing::warn!("No PKCS#11 module, using software signing (TEST ONLY)");
            let test_key = pkcs11::MockPrivateKey::create()?;
            match request.signature_type {
                SignatureType::Attached => {
                    cades::create_attached_signature(&content, &token_cert.der_bytes, &test_key)?
                }
                SignatureType::Detached => {
                    cades::create_detached_signature(&content, &token_cert.der_bytes, &test_key)?
                }
            }
        };

        // Write signature to file
        std::fs::write(&output_path, &signature_data)
            .map_err(|e| AppError::Io(format!("Failed to write signature: {}", e)))?;

        Ok(SignatureResult {
            success: true,
            output_path,
            message: "Документът е успешно подписан".to_string(),
        })
    }

    /// Sign using PKCS#11 token
    fn sign_with_token(
        &self,
        content: &[u8],
        token_cert: &TokenCertificate,
        sig_type: SignatureType,
        pkcs11: &Pkcs11Module,
    ) -> Result<Vec<u8>, AppError> {
        // Get private key handle
        let priv_key = token_cert.private_key_handle
            .ok_or_else(|| AppError::Pkcs11("No private key available".to_string()))?;

        tracing::info!("Signing with token (private key handle: {:?})", priv_key);

        // Use CMS builder to create CAdES signature with PKCS#11
        match sig_type {
            SignatureType::Attached => {
                cms_builder::build_cades_attached_signature(
                    content,
                    &token_cert.der_bytes,
                    pkcs11,
                    priv_key,
                )
            }
            SignatureType::Detached => {
                cms_builder::build_cades_detached_signature(
                    content,
                    &token_cert.der_bytes,
                    pkcs11,
                    priv_key,
                )
            }
        }
    }

    /// Verify a signature
    pub fn verify_signature(
        &self,
        signature_path: &PathBuf,
        original_path: Option<&PathBuf>,
    ) -> Result<bool, AppError> {
        let signature_data = std::fs::read(signature_path)
            .map_err(|e| AppError::Io(format!("Failed to read signature: {}", e)))?;

        let original_data = if let Some(path) = original_path {
            Some(std::fs::read(path).map_err(|e| AppError::Io(format!("Failed to read original: {}", e)))?)
        } else {
            None
        };

        cades::verify_signature(&signature_data, original_data.as_deref(), None)
    }

    /// Get slot info
    pub fn get_slot_info(&self) -> Result<String, AppError> {
        if let Some(ref pkcs11) = self.pkcs11 {
            match pkcs11.get_slot_info() {
                Ok(_) => Ok("PKCS#11 slot available".to_string()),
                Err(e) => Err(AppError::Pkcs11(e.to_string()))
            }
        } else {
            Err(AppError::Pkcs11("Not initialized".to_string()))
        }
    }
}

impl Default for SigningService {
    fn default() -> Self {
        Self::new()
    }
}
