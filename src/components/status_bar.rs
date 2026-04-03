use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct StatusBarProps {
    pub message: String,
}

#[component]
pub fn StatusBar(props: StatusBarProps) -> Element {
    let (icon, class) = if props.message.starts_with("✅") {
        ("✅", "status-success")
    } else if props.message.contains("Грешка") || props.message.starts_with("❌") {
        ("❌", "status-error")
    } else if props.message.contains("...") {
        ("⏳", "status-loading")
    } else {
        ("ℹ️", "status-info")
    };

    rsx! {
        footer { class: "status-bar {class}",
            span { class: "status-icon", "{icon}" }
            span { class: "status-message", "{props.message}" }
        }
    }
}
