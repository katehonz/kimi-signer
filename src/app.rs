use crate::crypto::{SigningService, TokenCertificate};
use crate::models::{CertificateInfo, SignatureType};
use crate::utils::{AppConfig, Pkcs11LibraryInfo};
use std::path::PathBuf;

pub struct DesktopSignerApp {
    // File selection
    pub selected_file: Option<PathBuf>,

    // Signature configuration
    pub signature_type: SignatureType,
    pub output_path: Option<PathBuf>,

    // Certificate selection
    pub selected_certificate: Option<CertificateInfo>,
    pub token_certificates: Vec<TokenCertificate>,
    pub certificates: Vec<CertificateInfo>, // For UI display

    // PIN entry
    pub pin: String,
    pub show_pin_dialog: bool,

    // Status
    pub status_message: String,
    pub is_signing: bool,
    pub signature_result: Option<String>,

    // Services
    pub signing_service: SigningService,

    // Configuration
    pub config: AppConfig,

    // UI State
    pub show_settings: bool,
    pub available_libraries: Vec<Pkcs11LibraryInfo>,
    pub selected_library: Option<String>,
    pub show_library_selector: bool,
    pub custom_library_path: String,
    pub is_logged_in: bool,
}

impl DesktopSignerApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        // Load configuration
        let config = AppConfig::load();

        // Get available libraries
        let available_libraries = config.get_all_libraries();

        // Initialize signing service
        let signing_service = SigningService::new();

        // NOTE: We do NOT auto-load the saved library to prevent PIN blocking issues.
        // The user must manually click "Load Library" button to connect.
        // This prevents accidental login attempts with cached/empty PINs.
        let selected_library = config.pkcs11_library_path.clone();

        let mut app = Self {
            selected_file: None,
            signature_type: if config.default_signature_type == "detached" {
                SignatureType::Detached
            } else if config.default_signature_type == "pades" {
                SignatureType::PAdES
            } else {
                SignatureType::Attached
            },
            output_path: config.default_output_dir.clone(),
            selected_certificate: None,
            token_certificates: Vec::new(),
            certificates: Vec::new(),
            pin: String::new(),
            show_pin_dialog: false,
            status_message: "Готов за подписване".to_string(),
            is_signing: false,
            signature_result: None,
            signing_service,
            config,
            show_settings: false,
            available_libraries,
            selected_library,
            show_library_selector: false,
            custom_library_path: String::new(),
            is_logged_in: false,
        };

        // Do NOT auto-refresh certificates on startup to prevent PIN blocking.
        // User must manually login first.
        app
    }

    /// Load the saved library from config (user must click button)
    pub fn load_saved_library(&mut self) {
        if let Some(ref lib_path) = self.selected_library {
            let path = std::path::Path::new(lib_path);
            if let Err(e) = crate::utils::validate_library_path(path) {
                self.status_message = format!("❌ {}", e);
                self.selected_library = None;
                self.config.pkcs11_library_path = None;
                let _ = self.config.save();
                return;
            }
            self.status_message = format!("Зареждане на библиотека: {}", lib_path);

                match self.signing_service.initialize_pkcs11(lib_path) {
                    Ok(_) => {
                        self.status_message =
                            "✓ Библиотеката е заредена. Моля, въведете ПИН.".to_string();
                    }
                    Err(e) => {
                        self.status_message = format!("❌ Грешка при зареждане: {}", e);
                    }
                }
        }
    }

    /// Select PKCS#11 library
    pub fn select_library(&mut self, path: &str) {
        self.status_message = format!("Зареждане на библиотека: {}", path);

        // Save to config
        self.config.set_active_library(path);
        self.selected_library = Some(path.to_string());

        // Initialize PKCS#11
        match self.signing_service.initialize_pkcs11(path) {
            Ok(_) => {
                self.status_message = "✓ Библиотеката е заредена".to_string();
                self.is_logged_in = false;
                self.token_certificates.clear();
                self.certificates.clear();
                self.selected_certificate = None;

                // Save config
                if let Err(e) = self.config.save() {
                    tracing::error!("Failed to save config: {}", e);
                }
            }
            Err(e) => {
                self.status_message = format!("❌ Грешка при зареждане: {}", e);
            }
        }
    }

    /// Add custom library path
    pub fn add_custom_library(&mut self) {
        if self.custom_library_path.is_empty() {
            return;
        }

        let path = self.custom_library_path.clone();
        let path_buf = PathBuf::from(&path);

        // Validate library path
        if let Err(e) = crate::utils::validate_library_path(&path_buf) {
            self.status_message = format!("❌ {}", e);
            return;
        }

        // Add to config
        let name = path_buf
            .file_stem()
            .and_then(|n| n.to_str())
            .unwrap_or("Custom")
            .to_string();

        if let Err(e) = crate::utils::validate_name(&name) {
            self.status_message = format!("❌ {}", e);
            return;
        }

        self.config.add_pkcs11_library(&name, &path, None);

        // Update available libraries
        self.available_libraries = self.config.get_all_libraries();

        // Select it
        self.select_library(&path);

        self.custom_library_path.clear();

        // Save config
        if let Err(e) = self.config.save() {
            tracing::error!("Failed to save config: {}", e);
        }
    }

    /// Browse for custom library
    pub fn browse_for_library(&mut self) {
        #[cfg(target_os = "windows")]
        let filter = rfd::FileDialog::new().add_filter("PKCS#11 Library", &["dll"]);

        #[cfg(target_os = "linux")]
        let filter = rfd::FileDialog::new().add_filter("PKCS#11 Library", &["so"]);

        #[cfg(target_os = "macos")]
        let filter = rfd::FileDialog::new().add_filter("PKCS#11 Library", &["dylib", "so"]);

        if let Some(path) = filter.pick_file() {
            self.custom_library_path = path.to_string_lossy().to_string();
        }
    }

    /// Login to token
    pub fn login(&mut self) {
        if let Err(e) = crate::utils::validate_pin(&self.pin) {
            self.status_message = format!("❌ {}", e);
            return;
        }

        self.status_message = "Вход в токен...".to_string();

        match self.signing_service.login(&self.pin) {
            Ok(_) => {
                self.is_logged_in = true;
                self.status_message = "✓ Успешен вход".to_string();
                self.pin.clear();
                self.refresh_certificates();
            }
            Err(e) => {
                self.status_message = format!("❌ Грешен ПИН: {}", e);
                self.pin.clear();
            }
        }
    }

    /// Logout from token
    pub fn logout(&mut self) {
        if let Err(e) = self.signing_service.logout() {
            tracing::error!("Logout error: {}", e);
        }
        self.is_logged_in = false;
        self.token_certificates.clear();
        self.certificates.clear();
        self.selected_certificate = None;
        self.status_message = "Излязохте от токена".to_string();
    }

    /// Load certificates from token
    pub fn refresh_certificates(&mut self) {
        if !self.signing_service.is_initialized() {
            self.status_message = "❌ Моля, първо изберете PKCS#11 библиотека".to_string();
            return;
        }

        if !self.is_logged_in {
            self.status_message = "❌ Моля, първо влезте с ПИН".to_string();
            return;
        }

        self.status_message = "Зареждане на сертификати...".to_string();

        match self.signing_service.get_certificates() {
            Ok(token_certs) => {
                self.token_certificates = token_certs.clone();
                self.certificates = token_certs.iter().map(|tc| tc.info.clone()).collect();

                if self.certificates.is_empty() {
                    self.status_message = "⚠ Няма намерени сертификати в токена".to_string();
                } else {
                    self.status_message =
                        format!("✓ Открити са {} сертификата", self.certificates.len());
                }
            }
            Err(e) => {
                self.status_message = format!("❌ Грешка: {}", e);
            }
        }
    }

    pub fn select_file(&mut self) {
        if let Some(path) = rfd::FileDialog::new().pick_file() {
            // Validate file size immediately
            if let Err(e) = crate::utils::validate_file_size(&path) {
                self.status_message = format!("❌ {}", e);
                return;
            }
            self.selected_file = Some(path.clone());
            self.status_message = "Документ избран".to_string();
            self.signature_result = None;

            if let Some(ext) = path.extension() {
                if ext.to_string_lossy().to_lowercase() == "pdf" {
                    self.signature_type = SignatureType::PAdES;
                    self.status_message =
                        "PDF документ избран - автоматично избран PAdES подпис".to_string();
                } else if self.signature_type == SignatureType::PAdES {
                    self.signature_type = SignatureType::Attached;
                }
            }
        }
    }

    pub fn select_output_dir(&mut self) {
        if let Some(path) = rfd::FileDialog::new().pick_folder() {
            if let Err(e) = crate::utils::validate_directory_writable(&path) {
                self.status_message = format!("❌ {}", e);
                return;
            }
            self.output_path = Some(path.clone());
            self.config.default_output_dir = Some(path);
            // Save config
            if let Err(e) = self.config.save() {
                tracing::error!("Failed to save config: {}", e);
            }
        }
    }

    pub fn start_signing(&mut self) {
        if self.selected_file.is_none() {
            self.status_message = "❌ Моля, изберете файл за подписване".to_string();
            return;
        }

        if self.selected_certificate.is_none() {
            self.status_message = "❌ Моля, изберете сертификат".to_string();
            return;
        }

        if !self.is_logged_in {
            self.status_message = "❌ Моля, първо влезте с ПИН".to_string();
            return;
        }

        // Warn if certificate is expired or not yet valid
        if let Some(ref cert) = self.selected_certificate {
            if !cert.is_valid() {
                self.status_message = format!(
                    "⚠ Предупреждение: Сертификатът е {}.",
                    match cert.validity_status() {
                        crate::models::CertificateValidity::Expired => "с изтекъл срок",
                        crate::models::CertificateValidity::NotYetValid => "все още невалиден",
                        _ => "",
                    }
                );
            }
        }

        self.show_pin_dialog = true;
    }

    pub fn perform_signing(&mut self) {
        if let Err(e) = crate::utils::validate_pin(&self.pin) {
            self.status_message = format!("❌ {}", e);
            return;
        }

        self.is_signing = true;
        self.status_message = "Подписване...".to_string();

        // Find the token certificate matching the selected certificate
        let selected_thumbprint = self
            .selected_certificate
            .as_ref()
            .map(|c| c.thumbprint.clone())
            .unwrap_or_default();

        let token_cert = match self
            .token_certificates
            .iter()
            .find(|tc| tc.info.thumbprint == selected_thumbprint)
        {
            Some(cert) => cert.clone(),
            None => {
                self.status_message = "❌ Не е намерен сертификат в токена".to_string();
                self.is_signing = false;
                self.pin.clear();
                return;
            }
        };

        // Validate file size before reading
        if let Some(ref path) = self.selected_file {
            if let Err(e) = crate::utils::validate_file_size(path) {
                self.status_message = format!("❌ {}", e);
                self.is_signing = false;
                self.pin.clear();
                return;
            }
        }

        // Read the document content
        let content = match self.selected_file.as_ref() {
            Some(path) => match std::fs::read(path) {
                Ok(data) => data,
                Err(e) => {
                    self.status_message = format!("❌ Грешка при четене на файл: {}", e);
                    self.is_signing = false;
                    self.pin.clear();
                    return;
                }
            },
            None => {
                self.status_message = "❌ Не е избран файл".to_string();
                self.is_signing = false;
                self.pin.clear();
                return;
            }
        };

        // Determine output path
        let output_path = match self.output_path.as_ref() {
            Some(dir) => {
                if let Err(e) = crate::utils::validate_directory_writable(dir) {
                    self.status_message = format!("❌ {}", e);
                    self.is_signing = false;
                    self.pin.clear();
                    return;
                }
                let file_name = self
                    .selected_file
                    .as_ref()
                    .and_then(|p| p.file_stem())
                    .and_then(|s| s.to_str())
                    .unwrap_or("signed");
                let ext = match self.signature_type {
                    SignatureType::PAdES => {
                        let original_ext = self
                            .selected_file
                            .as_ref()
                            .and_then(|p| p.extension())
                            .and_then(|s| s.to_str())
                            .unwrap_or("pdf");
                        format!("_signed.{}", original_ext)
                    }
                    _ => self.signature_type.extension().to_string(),
                };
                dir.join(format!("{}{}", file_name, ext))
            }
            None => {
                let input_path = self.selected_file.as_ref().unwrap();
                let parent = input_path
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."));
                // Validate parent directory is writable
                if let Err(e) = crate::utils::validate_directory_writable(parent) {
                    self.status_message = format!("❌ {}", e);
                    self.is_signing = false;
                    self.pin.clear();
                    return;
                }
                let file_name = input_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("signed");
                let ext = match self.signature_type {
                    SignatureType::PAdES => {
                        let original_ext = input_path
                            .extension()
                            .and_then(|s| s.to_str())
                            .unwrap_or("pdf");
                        format!("_signed.{}", original_ext)
                    }
                    _ => self.signature_type.extension().to_string(),
                };
                parent.join(format!("{}{}", file_name, ext))
            }
        };

        // Perform the signing using crypto module
        let signature_data = match self.signature_type {
            SignatureType::Attached => {
                match self.create_attached_signature(&content, &token_cert) {
                    Ok(data) => data,
                    Err(e) => {
                        self.status_message = format!("❌ Грешка при създаване на подпис: {}", e);
                        self.is_signing = false;
                        self.pin.clear();
                        return;
                    }
                }
            }
            SignatureType::Detached => {
                match self.create_detached_signature(&content, &token_cert) {
                    Ok(data) => data,
                    Err(e) => {
                        self.status_message = format!("❌ Грешка при създаване на подпис: {}", e);
                        self.is_signing = false;
                        self.pin.clear();
                        return;
                    }
                }
            }
            SignatureType::PAdES => match self.create_pades_signature(&content, &token_cert) {
                Ok(data) => data,
                Err(e) => {
                    self.status_message = format!("❌ Грешка при създаване на PAdES подпис: {}", e);
                    self.is_signing = false;
                    self.pin.clear();
                    return;
                }
            },
        };

        // Write the signature to file
        match std::fs::write(&output_path, &signature_data) {
            Ok(_) => {
                self.signature_result = Some(output_path.display().to_string());
                self.status_message = format!(
                    "✅ Документът е успешно подписан: {}",
                    output_path.display()
                );
            }
            Err(e) => {
                self.status_message = format!("❌ Грешка при запис на файл: {}", e);
            }
        }

        self.is_signing = false;
        self.show_pin_dialog = false;
        self.pin.clear();
    }

    /// Create attached signature using the token
    fn create_attached_signature(
        &self,
        content: &[u8],
        token_cert: &TokenCertificate,
    ) -> Result<Vec<u8>, String> {
        use crate::crypto::cms_builder;

        if let Some(ref pkcs11) = self.signing_service.get_pkcs11_module() {
            match cms_builder::build_cades_attached_signature(
                content,
                &token_cert.der_bytes,
                pkcs11,
                token_cert.private_key_handle.ok_or("No private key")?,
            ) {
                Ok(data) => Ok(data),
                Err(e) => Err(format!("CMS builder error: {:?}", e)),
            }
        } else {
            Err("PKCS#11 not initialized".to_string())
        }
    }

    /// Create detached signature using the token
    fn create_detached_signature(
        &self,
        content: &[u8],
        token_cert: &TokenCertificate,
    ) -> Result<Vec<u8>, String> {
        use crate::crypto::cms_builder;

        if let Some(ref pkcs11) = self.signing_service.get_pkcs11_module() {
            match cms_builder::build_cades_detached_signature(
                content,
                &token_cert.der_bytes,
                pkcs11,
                token_cert.private_key_handle.ok_or("No private key")?,
            ) {
                Ok(data) => Ok(data),
                Err(e) => Err(format!("CMS builder error: {:?}", e)),
            }
        } else {
            Err("PKCS#11 not initialized".to_string())
        }
    }

    /// Create PAdES signature (embedded in PDF) using the token
    fn create_pades_signature(
        &self,
        content: &[u8],
        token_cert: &TokenCertificate,
    ) -> Result<Vec<u8>, String> {
        use crate::crypto::pades;

        let signer_name = self
            .selected_certificate
            .as_ref()
            .map(|c| c.subject.clone())
            .unwrap_or_else(|| "Unknown Signer".to_string());

        if let Some(ref pkcs11) = self.signing_service.get_pkcs11_module() {
            match pades::sign_pdf_pades(
                content,
                &token_cert.der_bytes,
                pkcs11,
                token_cert.private_key_handle.ok_or("No private key")?,
                &signer_name,
            ) {
                Ok(data) => Ok(data),
                Err(e) => Err(format!("PAdES error: {}", e)),
            }
        } else {
            Err("PKCS#11 not initialized".to_string())
        }
    }
}

impl eframe::App for DesktopSignerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Top panel with title
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.add_space(10.0);
            ui.heading("📝 KIMI Signer");
            ui.label("Open Source приложение за електронно подписване (CAdES/PKCS#7)");
            ui.add_space(10.0);
            ui.separator();
        });

        // Bottom panel with status
        egui::TopBottomPanel::bottom("bottom_panel").show(ctx, |ui| {
            ui.add_space(5.0);

            let (icon, color) = if self.status_message.starts_with("✅")
                || self.status_message.starts_with("✓")
            {
                ("✅", egui::Color32::GREEN)
            } else if self.status_message.starts_with("❌") {
                ("❌", egui::Color32::RED)
            } else if self.is_signing {
                ("⏳", egui::Color32::YELLOW)
            } else {
                ("ℹ️", ui.style().visuals.text_color())
            };

            ui.colored_label(color, format!("{} {}", icon, self.status_message));
            ui.add_space(5.0);
        });

        // Central panel with main content
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(20.0);

            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.set_max_width(800.0);

                    // Section 0: PKCS#11 Library Selection (NEW)
                    self.render_library_section(ui);

                    ui.add_space(20.0);

                    // Section 1: File Selection
                    self.render_file_section(ui);

                    ui.add_space(20.0);

                    // Section 2: Signature Configuration
                    self.render_config_section(ui);

                    ui.add_space(20.0);

                    // Section 3: Login & Certificate Selection
                    self.render_certificate_section(ui);

                    ui.add_space(20.0);

                    // Section 4: Sign Button
                    self.render_sign_button(ui);
                });
            });
        });

        // PIN Dialog
        if self.show_pin_dialog {
            self.render_pin_dialog(ctx);
        }

        // Settings Window
        if self.show_settings {
            self.render_settings_window(ctx);
        }

        // Library Selector Window
        if self.show_library_selector {
            self.render_library_selector(ctx);
        }
    }
}

impl DesktopSignerApp {
    /// Render PKCS#11 library selection section
    fn render_library_section(&mut self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_min_width(700.0);
            ui.heading("0. Избор на PKCS#11 библиотека");
            ui.add_space(10.0);

            // Show current selection
            if let Some(ref lib) = self.selected_library {
                ui.horizontal(|ui| {
                    ui.label("Запаметена библиотека:");
                    ui.colored_label(egui::Color32::GREEN, lib);

                    if ui.button("🔄 Промени").clicked() {
                        self.show_library_selector = true;
                    }
                });

                // Show token status
                if self.signing_service.is_initialized() {
                    if self.is_logged_in {
                        ui.horizontal(|ui| {
                            ui.colored_label(egui::Color32::GREEN, "✓ Токенът е свързан");
                            if ui.button("Изход").clicked() {
                                self.logout();
                            }
                        });
                    } else {
                        ui.colored_label(egui::Color32::YELLOW, "⚠ Не сте влезли в токена");
                    }
                } else {
                    // Library path is saved but not loaded - show load button
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        ui.colored_label(egui::Color32::YELLOW, "⚠ Библиотеката не е заредена");
                        if ui.button("🔄 Зареди библиотеката").clicked() {
                            self.load_saved_library();
                        }
                    });
                }
            } else {
                ui.colored_label(egui::Color32::RED, "⚠ Не е избрана библиотека");
                if ui.button("📁 Избери библиотека").clicked() {
                    self.show_library_selector = true;
                }
            }
        });
    }

    /// Render library selector window
    fn render_library_selector(&mut self, ctx: &egui::Context) {
        let mut is_open = self.show_library_selector;

        egui::Window::new("Избор на PKCS#11 библиотека")
            .open(&mut is_open)
            .resizable(true)
            .default_size([500.0, 400.0])
            .show(ctx, |ui| {
                ui.label("Изберете библиотека за вашия токен:");
                ui.add_space(10.0);

                // Detected libraries
                if !self.available_libraries.is_empty() {
                    ui.strong("Открити библиотеки:");

                    let mut selected_path: Option<String> = None;

                    egui::ScrollArea::vertical()
                        .max_height(150.0)
                        .show(ui, |ui| {
                            for lib in &self.available_libraries {
                                let is_selected = self.selected_library.as_ref() == Some(&lib.path);

                                let response = ui.selectable_label(
                                    is_selected,
                                    format!("{}\n  {}", lib.name, lib.path),
                                );

                                if response.clicked() {
                                    selected_path = Some(lib.path.clone());
                                }

                                if let Some(ref desc) = lib.description {
                                    ui.small(format!("  {}", desc));
                                }

                                ui.add_space(5.0);
                            }
                        });

                    // Handle selection outside the closure
                    if let Some(path) = selected_path {
                        self.select_library(&path);
                        self.show_library_selector = false;
                    }
                } else {
                    ui.label("Не са открити библиотеки.");
                }

                ui.separator();
                ui.add_space(10.0);

                // Custom library path
                ui.strong("Или посочете ръчно:");
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(&mut self.custom_library_path);
                    if ui.button("📁 Преглед").clicked() {
                        self.browse_for_library();
                    }
                });

                if ui.button("Добави библиотека").clicked() {
                    self.add_custom_library();
                    self.show_library_selector = false;
                }

                ui.add_space(10.0);
                ui.separator();

                ui.label("💡 Съвети:");
                ui.small("• Gemalto: обикновено eTPKCS11.dll (Windows) или libeTPkcs11.so (Linux)");
                ui.small("• B-Trust: btrustpkcs11.dll");
                ui.small("• InfoNotary: innp11.dll");
                ui.small("• Файлът обикновено е в C:\\Windows\\System32\\ или /usr/lib/");
            });

        self.show_library_selector = is_open;
    }

    fn render_file_section(&mut self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_min_width(700.0);
            ui.heading("1. Избор на документ");
            ui.add_space(10.0);

            if ui.button("📁 Изберете файл").clicked() {
                self.select_file();
            }

            if let Some(ref path) = self.selected_file {
                ui.add_space(10.0);
                ui.group(|ui| {
                    ui.colored_label(egui::Color32::GREEN, format!("✓ {}", path.display()));
                });
            }
        });
    }

    fn render_config_section(&mut self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_min_width(700.0);
            ui.heading("2. Конфигурация на подписа");
            ui.add_space(10.0);

            let is_pdf = self.selected_file.as_ref()
                .and_then(|p| p.extension())
                .map(|e| e.to_string_lossy().to_lowercase() == "pdf")
                .unwrap_or(false);

            // Signature type
            ui.horizontal(|ui| {
                ui.label("Тип на подписа:");
                
                let mut changed = false;
                
                if ui.radio(self.signature_type == SignatureType::Attached, "Attached (.p7m)").clicked() {
                    self.signature_type = SignatureType::Attached;
                    changed = true;
                }
                
                if ui.radio(self.signature_type == SignatureType::Detached, "Detached (.p7s)").clicked() {
                    self.signature_type = SignatureType::Detached;
                    changed = true;
                }

                let pades_label = if is_pdf { "PAdES (.pdf) ✓" } else { "PAdES (.pdf)" };
                if ui.radio(self.signature_type == SignatureType::PAdES, pades_label).clicked() {
                    if is_pdf || self.selected_file.is_none() {
                        self.signature_type = SignatureType::PAdES;
                        changed = true;
                    }
                }

                if !is_pdf && self.selected_file.is_some() {
                    ui.colored_label(egui::Color32::GRAY, "(само за PDF)");
                }
                
                if changed {
                    self.config.default_signature_type = match self.signature_type {
                        SignatureType::Attached => "attached".to_string(),
                        SignatureType::Detached => "detached".to_string(),
                        SignatureType::PAdES => "pades".to_string(),
                    };
                    if let Err(e) = self.config.save() {
                        tracing::error!("Failed to save config: {}", e);
                    }
                }
            });

            ui.add_space(10.0);

            // Output path
            ui.horizontal(|ui| {
                ui.label("Запиши резултата в:");
                
                let output_text = self.output_path.as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "Автоматично (същата папка)".to_string());
                
                ui.label(output_text);
                
                if ui.button("📁 Избор").clicked() {
                    self.select_output_dir();
                }
            });

            ui.add_space(10.0);

            // Info box
            ui.group(|ui| {
                let info_text = match self.signature_type {
                    SignatureType::Attached => "📌 Attached подписът е вграден в самия документ. Подписаният файл има разширение .p7m и съдържа оригиналния документ + подписа.",
                    SignatureType::Detached => "📌 Detached подписът се съхранява в отделен файл с разширение .p7s. Оригиналният документ остава непроменен.",
                    SignatureType::PAdES => "📌 PAdES подписът е вграден директно в PDF файла. Разширението остава .pdf. В долния ляв ъгъл се поставя визуален печат.",
                };
                ui.colored_label(egui::Color32::BLUE, info_text);
            });
        });
    }

    fn render_certificate_section(&mut self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.set_min_width(700.0);
            ui.heading("3. Вход и избор на сертификат");
            ui.add_space(10.0);

            // Login section
            if self.signing_service.is_initialized() && !self.is_logged_in {
                ui.group(|ui| {
                    ui.label("Вход в токен с ПИН код:");
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.pin)
                                .password(true)
                                .hint_text("ПИН код"),
                        );

                        if ui.button("Вход").clicked() {
                            self.login();
                        }
                    });
                });
                ui.add_space(10.0);
            }

            // Certificate list
            if self.is_logged_in {
                ui.horizontal(|ui| {
                    if ui.button("🔄 Обнови списъка").clicked() {
                        self.refresh_certificates();
                    }
                });

                ui.add_space(10.0);

                if self.certificates.is_empty() {
                    ui.colored_label(
                        egui::Color32::GRAY,
                        "Няма намерени сертификати. Натиснете 'Обнови списъка'.",
                    );
                } else {
                    egui::ScrollArea::vertical()
                        .max_height(200.0)
                        .show(ui, |ui| {
                            for cert in &self.certificates {
                                let is_selected = self
                                    .selected_certificate
                                    .as_ref()
                                    .map(|s| s.thumbprint == cert.thumbprint)
                                    .unwrap_or(false);

                                let response = ui.selectable_label(
                                    is_selected,
                                    format!(
                                        "{}\nИздател: {} | Валиден до: {}",
                                        cert.subject,
                                        cert.issuer,
                                        cert.valid_to.format("%d.%m.%Y")
                                    ),
                                );

                                if response.clicked() {
                                    self.selected_certificate = Some(cert.clone());
                                }

                                if cert.is_valid() {
                                    ui.colored_label(egui::Color32::GREEN, "  ✓ Валиден");
                                } else {
                                    ui.colored_label(egui::Color32::RED, "  ✗ Невалиден");
                                }

                                ui.add_space(5.0);
                            }
                        });
                }
            } else {
                ui.colored_label(
                    egui::Color32::GRAY,
                    "Моля, първо влезте в токена с ПИН код.",
                );
            }

            // Selected certificate details
            if let Some(ref cert) = self.selected_certificate {
                ui.add_space(10.0);
                ui.group(|ui| {
                    ui.strong("Избран сертификат:");
                    ui.label(format!("Собственик: {}", cert.subject));
                    ui.label(format!("Издател: {}", cert.issuer));
                    ui.label(format!("Сериен номер: {}", cert.serial_number));
                    ui.label(format!(
                        "Валиден от: {}",
                        cert.valid_from.format("%d.%m.%Y %H:%M")
                    ));
                    ui.label(format!(
                        "Валиден до: {}",
                        cert.valid_to.format("%d.%m.%Y %H:%M")
                    ));
                });
            }
        });
    }

    fn render_sign_button(&mut self, ui: &mut egui::Ui) {
        let can_sign = self.selected_file.is_some()
            && self.selected_certificate.is_some()
            && self.is_logged_in
            && !self.is_signing;

        let button_text = if self.is_signing {
            "⏳ Подписване..."
        } else {
            "✍️ Подпиши документа"
        };

        ui.vertical_centered(|ui| {
            let button = egui::Button::new(button_text)
                .min_size(egui::Vec2::new(250.0, 50.0))
                .fill(if can_sign {
                    ui.style().visuals.selection.bg_fill
                } else {
                    ui.style().visuals.widgets.inactive.bg_fill
                });

            let response = ui.add_sized([250.0, 50.0], button);

            if response.clicked() && can_sign {
                self.start_signing();
            }
        });

        // Show result
        if let Some(ref result) = self.signature_result {
            ui.add_space(10.0);
            ui.colored_label(
                egui::Color32::GREEN,
                format!("✅ Създаден файл: {}", result),
            );
        }
    }

    fn render_pin_dialog(&mut self, ctx: &egui::Context) {
        egui::Window::new("Въвеждане на ПИН код за подписване")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .default_size([400.0, 200.0])
            .min_size([350.0, 180.0])
            .show(ctx, |ui| {
                ui.label("Моля, въведете ПИН кода на вашия токен за подписване:");

                ui.add_space(10.0);

                ui.add(
                    egui::TextEdit::singleline(&mut self.pin)
                        .password(true)
                        .hint_text("ПИН код"),
                );

                ui.add_space(20.0);

                ui.horizontal(|ui| {
                    if ui.button("Отказ").clicked() {
                        self.show_pin_dialog = false;
                        self.pin.clear();
                    }

                    if ui.button("Подпиши").clicked() {
                        self.perform_signing();
                    }
                });
            });
    }

    fn render_settings_window(&mut self, ctx: &egui::Context) {
        egui::Window::new("Настройки")
            .open(&mut self.show_settings)
            .resizable(true)
            .default_size([500.0, 400.0])
            .show(ctx, |ui| {
                ui.heading("PKCS#11 Библиотеки");

                ui.label("Налични библиотеки:");
                for lib in &self.available_libraries {
                    ui.label(format!("• {}: {}", lib.name, lib.path));
                }

                ui.add_space(20.0);
                ui.separator();

                if ui.button("🔄 Обнови списъка с библиотеки").clicked() {
                    self.available_libraries = self.config.get_all_libraries();
                }
            });
    }
}
