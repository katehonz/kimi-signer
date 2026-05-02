//! Configuration management for KIMI Signer
//! 
//! Stores user preferences including the selected PKCS#11 library path

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Path to the selected PKCS#11 library
    pub pkcs11_library_path: Option<String>,
    
    /// Default output directory for signed files
    pub default_output_dir: Option<PathBuf>,
    
    /// Last used signature type
    pub default_signature_type: String,
    
    /// Whether to auto-detect tokens on startup
    pub auto_detect_token: bool,
    
    /// List of manually added PKCS#11 libraries
    pub custom_pkcs11_libraries: Vec<Pkcs11LibraryInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pkcs11LibraryInfo {
    pub name: String,
    pub path: String,
    pub description: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            pkcs11_library_path: None,
            default_output_dir: None,
            default_signature_type: "attached".to_string(),
            auto_detect_token: true,
            custom_pkcs11_libraries: Vec::new(),
        }
    }
}

impl AppConfig {
    /// Load configuration from file
    pub fn load() -> Self {
        let config_path = get_config_path();
        if let Ok(content) = std::fs::read_to_string(&config_path) {
            if let Ok(config) = toml::from_str(&content) {
                return config;
            }
        }
        Self::default()
    }

    /// Save configuration to file
    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config_path = get_config_path();
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        std::fs::write(config_path, content)?;
        Ok(())
    }

    /// Add a custom PKCS#11 library
    pub fn add_pkcs11_library(&mut self, name: &str, path: &str, description: Option<&str>) {
        let trimmed_name = name.trim();
        if trimmed_name.is_empty() {
            tracing::warn!("Cannot add library with empty name");
            return;
        }
        let trimmed_path = path.trim();
        if trimmed_path.is_empty() {
            tracing::warn!("Cannot add library with empty path");
            return;
        }
        // Remove if already exists
        self.custom_pkcs11_libraries.retain(|lib| lib.path != trimmed_path);

        self.custom_pkcs11_libraries.push(Pkcs11LibraryInfo {
            name: trimmed_name.to_string(),
            path: trimmed_path.to_string(),
            description: description.map(|s| s.trim().to_string()),
        });
    }

    /// Remove a custom PKCS#11 library
    pub fn remove_pkcs11_library(&mut self, path: &str) {
        self.custom_pkcs11_libraries.retain(|lib| lib.path != path);
    }

    /// Set the active PKCS#11 library
    pub fn set_active_library(&mut self, path: &str) {
        self.pkcs11_library_path = Some(path.to_string());
    }

    /// Get all available PKCS#11 libraries (detected + custom)
    pub fn get_all_libraries(&self) -> Vec<Pkcs11LibraryInfo> {
        let mut libraries = Vec::new();
        
        // Add detected libraries
        let detected = detect_system_pkcs11_libraries();
        libraries.extend(detected);
        
        // Add custom libraries that exist
        for lib in &self.custom_pkcs11_libraries {
            if std::path::Path::new(&lib.path).exists() && !libraries.iter().any(|l| l.path == lib.path) {
                libraries.push(lib.clone());
            }
        }
        
        libraries
    }
}

/// Detect system PKCS#11 libraries
fn detect_system_pkcs11_libraries() -> Vec<Pkcs11LibraryInfo> {
    let mut libraries = Vec::new();

    // Common Bulgarian eID provider paths
    #[cfg(target_os = "windows")]
    let common_paths = [
        ("B-Trust", r"C:\Windows\System32\btrustpkcs11.dll", "B-Trust КЕП"),
        ("B-Trust (32-bit)", r"C:\Windows\SysWOW64\btrustpkcs11.dll", "B-Trust КЕП (32-bit)"),
        ("StampIT", r"C:\Windows\System32\STAMPP11.dll", "StampIT КЕП"),
        ("StampIT (32-bit)", r"C:\Windows\SysWOW64\STAMPP11.dll", "StampIT КЕП (32-bit)"),
        ("InfoNotary", r"C:\Windows\System32\innp11.dll", "InfoNotary КЕП"),
        ("InfoNotary (32-bit)", r"C:\Windows\SysWOW64\innp11.dll", "InfoNotary КЕП (32-bit)"),
        ("Bit4ID", r"C:\Windows\System32\bit4ipki.dll", "Bit4ID КЕП"),
        ("Bit4ID (32-bit)", r"C:\Windows\SysWOW64\bit4ipki.dll", "Bit4ID КЕП (32-bit)"),
        ("Gemalto", r"C:\Windows\System32\eTPKCS11.dll", "Gemalto IDPrime"),
        ("Gemalto (32-bit)", r"C:\Windows\SysWOW64\eTPKCS11.dll", "Gemalto IDPrime (32-bit)"),
        ("SafeNet", r"C:\Windows\System32\eTPKCS11.dll", "SafeNet eToken"),
        ("ActivIdentity", r"C:\Windows\System32\acpkcs211.dll", "ActivIdentity"),
    ];

    #[cfg(target_os = "linux")]
    let common_paths = [
        ("B-Trust", "/usr/lib/libbtrustpkcs11.so", "B-Trust КЕП"),
        ("B-Trust (x64)", "/usr/lib64/libbtrustpkcs11.so", "B-Trust КЕП"),
        ("B-Trust (multiarch)", "/usr/lib/x86_64-linux-gnu/libbtrustpkcs11.so", "B-Trust КЕП"),
        ("StampIT", "/usr/lib/libstampp11.so", "StampIT КЕП"),
        ("StampIT (x64)", "/usr/lib64/libstampp11.so", "StampIT КЕП"),
        ("InfoNotary", "/usr/lib/libinnp11.so", "InfoNotary КЕП"),
        ("InfoNotary (x64)", "/usr/lib64/libinnp11.so", "InfoNotary КЕП"),
        ("Bit4ID", "/usr/lib/libbit4ipki.so", "Bit4ID КЕП"),
        ("Bit4ID (x64)", "/usr/lib64/libbit4ipki.so", "Bit4ID КЕП"),
        ("Gemalto", "/usr/lib/libeTPkcs11.so", "Gemalto IDPrime"),
        ("Gemalto (x64)", "/usr/lib64/libeTPkcs11.so", "Gemalto IDPrime"),
        ("OpenSC", "/usr/lib/opensc-pkcs11.so", "OpenSC"),
        ("OpenSC (x64)", "/usr/lib64/opensc-pkcs11.so", "OpenSC"),
    ];

    #[cfg(target_os = "macos")]
    let common_paths = [
        ("B-Trust", "/usr/local/lib/libbtrustpkcs11.dylib", "B-Trust КЕП"),
        ("StampIT", "/usr/local/lib/libstampp11.dylib", "StampIT КЕП"),
        ("InfoNotary", "/usr/local/lib/libinnp11.dylib", "InfoNotary КЕП"),
        ("Gemalto", "/usr/local/lib/libeTPkcs11.dylib", "Gemalto IDPrime"),
        ("OpenSC", "/usr/local/lib/opensc-pkcs11.so", "OpenSC"),
    ];

    for (name, path, desc) in common_paths.iter() {
        if std::path::Path::new(path).exists() {
            libraries.push(Pkcs11LibraryInfo {
                name: name.to_string(),
                path: path.to_string(),
                description: Some(desc.to_string()),
            });
        }
    }

    libraries
}

fn get_config_path() -> PathBuf {
    let config_dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."));
    config_dir.join("desktop-signer").join("config.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert!(config.pkcs11_library_path.is_none());
        assert_eq!(config.default_signature_type, "attached");
    }

    #[test]
    fn test_add_library() {
        let mut config = AppConfig::default();
        config.add_pkcs11_library("Test", "/test/path.so", Some("Test lib"));
        assert_eq!(config.custom_pkcs11_libraries.len(), 1);
    }
}
