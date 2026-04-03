use eframe::NativeOptions;

mod app;
mod components;
mod crypto;
mod models;
mod utils;

use app::DesktopSignerApp;

fn main() -> eframe::Result {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    tracing::info!("Starting KIMI Signer application");

    let options = NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 700.0])
            .with_min_inner_size([600.0, 400.0]),
        ..Default::default()
    };

    eframe::run_native(
        "KIMI Signer - Електронно подписване",
        options,
        Box::new(|cc| Ok(Box::new(DesktopSignerApp::new(cc)))),
    )
}
