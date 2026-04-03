use std::path::PathBuf;

pub mod config;

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
