#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("Anonimator")
            .with_inner_size([1440.0, 820.0])
            .with_min_inner_size([1000.0, 560.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Anonimator",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}
