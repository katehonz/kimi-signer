use dioxus::prelude::*;

#[derive(Props, Clone, PartialEq)]
pub struct SignButtonProps {
    pub disabled: bool,
    pub is_loading: bool,
    pub on_click: EventHandler<()>,
}

#[component]
pub fn SignButton(props: SignButtonProps) -> Element {
    rsx! {
        button {
            class: if props.is_loading { "btn btn-sign loading" } else { "btn btn-sign" },
            disabled: props.disabled || props.is_loading,
            onclick: move |_| props.on_click.call(()),
            
            if props.is_loading {
                rsx! {
                    span { class: "spinner", "⏳" }
                    " Подписване..."
                }
            } else {
                rsx! {
                    "✍️ Подпиши документа"
                }
            }
        }
    }
}
