// MedCrypto Native Desktop GUI Launcher Example
// Author: Jeong Hoon Kim
//
// Usage:
//   cargo run --example gui_launcher

use medcrypto::gui::run_gui;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("==========================================================");
    println!("  MedCrypto: Launching Native Desktop GUI (eframe/egui)   ");
    println!("  Zero HTML / Zero Electron / Native Rust Performance     ");
    println!("==========================================================");

    if let Err(e) = run_gui() {
        eprintln!("[ERROR] Failed to run GUI: {}", e);
        std::process::exit(1);
    }

    Ok(())
}
