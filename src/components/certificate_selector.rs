use dioxus::prelude::*;
use crate::models::CertificateInfo;

#[derive(Props, Clone, PartialEq)]
pub struct CertificateSelectorProps {
    pub selected: Option<CertificateInfo>,
    pub on_select: EventHandler<CertificateInfo>,
}

#[component]
pub fn CertificateSelector(props: CertificateSelectorProps) -> Element {
    let mut certificates = use_signal(|| Vec::<CertificateInfo>::new());
    let mut is_loading = use_signal(|| false);
    let mut show_pin_dialog = use_signal(|| false);
    let mut pin_input = use_signal(|| String::new());

    // Load certificates from token
    let load_certificates = move |_| {
        is_loading.set(true);
        certificates.set(vec![
            // Mock certificates for now
            CertificateInfo {
                subject: "CN=Иван Иванов, OU=Борика, O=Борика АД, C=BG".to_string(),
                issuer: "CN=B-Trust Qualified CA, O=B-Trust, C=BG".to_string(),
                serial_number: "123456789ABC".to_string(),
                valid_from: chrono::Utc::now() - chrono::Duration::days(30),
                valid_to: chrono::Utc::now() + chrono::Duration::days(335),
                thumbprint: "A1:B2:C3:D4:E5:F6".to_string(),
                has_private_key: true,
            },
            CertificateInfo {
                subject: "CN=Георги Георгиев, OU=InfoNotary, O=InfoNotary, C=BG".to_string(),
                issuer: "CN=InfoNotary QES CA, O=InfoNotary, C=BG".to_string(),
                serial_number: "987654321XYZ".to_string(),
                valid_from: chrono::Utc::now() - chrono::Duration::days(100),
                valid_to: chrono::Utc::now() + chrono::Duration::days(265),
                thumbprint: "F6:E5:D4:C3:B2:A1".to_string(),
                has_private_key: true,
            },
        ]);
        is_loading.set(false);
    };

    rsx! {
        div { class: "certificate-selector",
            // Refresh button
            button {
                class: "btn btn-secondary refresh-btn",
                disabled: *is_loading.read(),
                onclick: load_certificates,
                if *is_loading.read() {
                    "🔄 Зареждане..."
                } else {
                    "🔄 Обнови списъка"
                }
            }

            // Certificate list
            if certificates.read().is_empty() {
                div { class: "no-certificates",
                    "Няма намерени сертификати. Моля, поставете токен/смарт карта и натиснете \"Обнови списъка\"."
                }
            } else {
                div { class: "certificate-list",
                    for cert in certificates.read().iter() {
                        div {
                            class: if props.selected.as_ref().map(|s| s.thumbprint == cert.thumbprint).unwrap_or(false) {
                                "certificate-item selected"
                            } else {
                                "certificate-item"
                            },
                            onclick: move |_| {
                                props.on_select.call(cert.clone());
                            },
                            div { class: "cert-subject", "{cert.subject}" }
                            div { class: "cert-details",
                                "Издател: {cert.issuer} | Валиден до: {cert.valid_to.format(\"%d.%m.%Y\")}"
                            }
                            if cert.is_valid() {
                                span { class: "cert-valid", "✓ Валиден" }
                            } else {
                                span { class: "cert-invalid", "✗ Невалиден" }
                            }
                        }
                    }
                }
            }

            // Selected certificate info
            if let Some(ref cert) = props.selected {
                div { class: "selected-cert-info",
                    h4 { "Избран сертификат:" }
                    table { class: "cert-info-table",
                        tbody {
                            tr {
                                td { "Собственик:" }
                                td { "{cert.subject}" }
                            }
                            tr {
                                td { "Издател:" }
                                td { "{cert.issuer}" }
                            }
                            tr {
                                td { "Сериен номер:" }
                                td { "{cert.serial_number}" }
                            }
                            tr {
                                td { "Валиден от:" }
                                td { "{cert.valid_from.format(\"%d.%m.%Y %H:%M\")}" }
                            }
                            tr {
                                td { "Валиден до:" }
                                td { "{cert.valid_to.format(\"%d.%m.%Y %H:%M\")}" }
                            }
                        }
                    }
                }
            }
        }
    }
}
