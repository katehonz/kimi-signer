use dioxus::prelude::*;
use std::path::PathBuf;

#[component]
pub fn FileSelector(on_select: EventHandler<PathBuf>) -> Element {
    let mut is_drag_over = use_signal(|| false);

    let handle_file_selection = move |path: PathBuf| {
        if path.exists() {
            on_select.call(path);
        }
    };

    rsx! {
        div {
            class: if *is_drag_over.read() { "file-selector drag-over" } else { "file-selector" },
            ondragover: move |e| {
                e.prevent_default();
                is_drag_over.set(true);
            },
            ondragleave: move |_| {
                is_drag_over.set(false);
            },
            ondrop: move |e| {
                e.prevent_default();
                is_drag_over.set(false);

                // Handle dropped files
                if let Some(data_transfer) = e.data_transfer() {
                    if let Some(files) = data_transfer.files() {
                        if let Some(file) = files.get(0) {
                            if let Some(path) = file.path() {
                                handle_file_selection(PathBuf::from(path));
                            }
                        }
                    }
                }
            },

            div { class: "file-selector-icon", "📄" }
            p { "Плъзнете файл тук или" }
            button {
                class: "btn btn-primary",
                onclick: move |_| {
                    spawn(async move {
                        if let Some(path) = rfd::AsyncFileDialog::new()
                            .add_filter("Всички файлове", &["*"])

                            .pick_file()
                            .await
                        {
                            handle_file_selection(PathBuf::from(path.path()));
                        }
                    });
                },
                "Изберете файл"
            }
        }
    }
}
