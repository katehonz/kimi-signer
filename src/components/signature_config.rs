use dioxus::prelude::*;
use crate::models::SignatureType;
use std::path::PathBuf;

#[derive(Props, Clone, PartialEq)]
pub struct SignatureConfigProps {
    pub signature_type: SignatureType,
    pub on_type_change: EventHandler<SignatureType>,
    pub output_path: Option<PathBuf>,
    pub on_output_change: EventHandler<PathBuf>,
}

#[component]
pub fn SignatureConfig(props: SignatureConfigProps) -> Element {
    let output_display = props.output_path.as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "Автоматично (същата папка)".to_string());

    rsx! {
        div { class: "signature-config",
            // Signature type selection
            div { class: "config-row",
                label { "Тип на подписа:" }
                select {
                    value: match props.signature_type {
                        SignatureType::Attached => "attached",
                        SignatureType::Detached => "detached",
                    },
                    onchange: move |e| {
                        let value = e.value();
                        let sig_type = match value.as_str() {
                            "attached" => SignatureType::Attached,
                            "detached" => SignatureType::Detached,
                            _ => SignatureType::Attached,
                        };
                        props.on_type_change.call(sig_type);
                    },
                    option { value: "attached", "{SignatureType::Attached.description()}" }
                    option { value: "detached", "{SignatureType::Detached.description()}" }
                }
            }

            // Output path selection
            div { class: "config-row",
                label { "Запиши резултата в:" }
                div { class: "output-path-row",
                    input {
                        class: "output-path-input",
                        readonly: true,
                        value: "{output_display}"
                    }
                    button {
                        class: "btn btn-secondary",
                        onclick: move |_| {
                            let on_change = props.on_output_change.clone();
                            spawn(async move {
                                if let Some(path) = rfd::AsyncFileDialog::new()
                                    .pick_folder()
                                    .await
                                {
                                    on_change.call(PathBuf::from(path.path()));
                                }
                            });
                        },
                        "📁 Избор"
                    }
                }
            }

            // Info box
            div { class: "info-box",
                match props.signature_type {
                    SignatureType::Attached => rsx! {
                        p { "📌 Attached подписът е вграден в самия документ. "
                            "Подписаният файл има разширение .p7m и съдържа оригиналния документ + подписа." }
                    },
                    SignatureType::Detached => rsx! {
                        p { "📌 Detached подписът се съхранява в отделен файл с разширение .p7s. "
                            "Оригиналният документ остава непроменен." }
                    },
                }
            }
        }
    }
}
