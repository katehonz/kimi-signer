use std::path::{Path, PathBuf};

pub mod config;

pub const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100 MB
pub const PIN_MIN_LENGTH: usize = 4;
pub const PIN_MAX_LENGTH: usize = 16;

// Re-export config types
pub use config::{AppConfig, Pkcs11LibraryInfo};

/// Get the default output directory for signed files
pub fn get_default_output_dir() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

/// Generate output filename based on input and signature type
pub fn generate_output_filename(
    input_path: &PathBuf,
    extension: &str,
    output_dir: Option<&PathBuf>,
) -> PathBuf {
    let stem = input_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("signed");
    
    let parent = output_dir
        .cloned()
        .or_else(|| input_path.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    
    parent.join(format!("{}{}", stem, extension))
}

/// Check if file is already signed
pub fn is_signed_file(path: &PathBuf) -> bool {
    if let Some(ext) = path.extension() {
        let ext = ext.to_string_lossy().to_lowercase();
        matches!(ext.as_str(), "p7m" | "p7s" | "p7c")
    } else {
        false
    }
}

/// Format file size for display
pub fn format_file_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut size = size as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    format!("{:.2} {}", size, UNITS[unit_index])
}

/// Validate PIN code
/// Returns Ok(()) if valid, or Err with description of the problem
pub fn validate_pin(pin: &str) -> Result<(), String> {
    if pin.is_empty() {
        return Err("ПИН кодът не може да бъде празен".to_string());
    }
    if pin.len() < PIN_MIN_LENGTH {
        return Err(format!(
            "ПИН кодът трябва да е поне {} символа",
            PIN_MIN_LENGTH
        ));
    }
    if pin.len() > PIN_MAX_LENGTH {
        return Err(format!(
            "ПИН кодът не може да е по-дълъг от {} символа",
            PIN_MAX_LENGTH
        ));
    }
    if !pin.chars().all(|c| c.is_ascii_graphic()) {
        return Err("ПИН кодът съдържа невалидни символи".to_string());
    }
    Ok(())
}

/// Validate that a library path appears to be a valid shared library
pub fn validate_library_path(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err("Файлът не съществува".to_string());
    }
    if !path.is_file() {
        return Err("Пътят не сочи към файл".to_string());
    }
    let valid_extensions: &[&str] = if cfg!(target_os = "windows") {
        &["dll"]
    } else if cfg!(target_os = "macos") {
        &["dylib", "so", "dll"]
    } else {
        &["so"]
    };
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    if !valid_extensions.contains(&ext) {
        return Err(format!(
            "Файлът не изглежда като споделена библиотека. Очаквано разширение: {}",
            valid_extensions.join(", ")
        ));
    }
    Ok(())
}

/// Validate that a file does not exceed the maximum allowed size
pub fn validate_file_size(path: &Path) -> Result<(), String> {
    let metadata = path
        .metadata()
        .map_err(|e| format!("Грешка при проверка на файла: {}", e))?;
    if metadata.len() > MAX_FILE_SIZE {
        return Err(format!(
            "Файлът е твърде голям: {}. Максимален размер: {}",
            format_file_size(metadata.len()),
            format_file_size(MAX_FILE_SIZE)
        ));
    }
    Ok(())
}

/// Validate that a directory is writable by attempting to create a test file
pub fn validate_directory_writable(dir: &Path) -> Result<(), String> {
    if !dir.exists() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("Не може да се създаде директория: {}", e))?;
    }
    let test_file = dir.join(".kimi_write_test");
    match std::fs::write(&test_file, b"test") {
        Ok(_) => {
            let _ = std::fs::remove_file(&test_file);
            Ok(())
        }
        Err(e) => Err(format!("Няма права за запис в директорията: {}", e)),
    }
}

/// Validate that a name string is non-empty and not too long
pub fn validate_name(name: &str) -> Result<(), String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("Името не може да бъде празно".to_string());
    }
    if trimmed.len() > 128 {
        return Err("Името е твърде дълго (максимум 128 символа)".to_string());
    }
    Ok(())
}

/// Get MIME type based on file extension
pub fn get_mime_type(path: &PathBuf) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("pdf") => "application/pdf",
        Some("xml") => "application/xml",
        Some("txt") => "text/plain",
        Some("doc") => "application/msword",
        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        Some("p7m") => "application/pkcs7-mime",
        Some("p7s") => "application/pkcs7-signature",
        _ => "application/octet-stream",
    }
}
