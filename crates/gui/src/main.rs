//! `rdisasm-gui` — interactive desktop front-end.

#![forbid(unsafe_code)]

mod app;
mod graph_view;
mod hex_view;

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Usage: rdisasm-gui [binary] [address|name]
    let path = std::env::args().nth(1);
    let goto = std::env::args().nth(2);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("rdisasm — Rust Disassembler & Decompiler")
            .with_inner_size([1440.0, 900.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native(
        "rdisasm",
        options,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, path, goto)))),
    )
}
