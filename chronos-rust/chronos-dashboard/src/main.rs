#![allow(non_snake_case)]

use dioxus::prelude::*;
use log::LevelFilter;

fn main() {
    // Init logger for web console
    wasm_logger::init(wasm_logger::Config::new(LevelFilter::Info));
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    let mut network_status = use_signal(|| "Connecting to Drand Beacon...");
    let mut fhe_status = use_signal(|| "Awaiting FHE Neural Network evaluation...");
    let mut dataset_loaded = use_signal(|| false);

    // Simulate connection flow
    use_effect(move || {
        let mut network_status = network_status.clone();
        let mut fhe_status = fhe_status.clone();
        let mut dataset_loaded = dataset_loaded.clone();

        spawn(async move {
            gloo_timers::future::sleep(std::time::Duration::from_millis(1500)).await;
            network_status.set("Drand Beacon Synced. Mission Seed Secured.");

            gloo_timers::future::sleep(std::time::Duration::from_millis(1000)).await;
            dataset_loaded.set(true);

            gloo_timers::future::sleep(std::time::Duration::from_millis(1500)).await;
            fhe_status.set("Evaluating 2-Layer TFHE Neural Network over 20,640 records...");
        });
    });

    rsx! {
        div {
            class: "min-h-screen bg-slate-900 text-white font-sans selection:bg-cyan-500 selection:text-slate-900",

            // Header
            header {
                class: "border-b border-slate-800 bg-slate-900/50 backdrop-blur-md sticky top-0 z-50",
                div {
                    class: "max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between",
                    div {
                        class: "flex items-center space-x-3",
                        div { class: "w-3 h-3 rounded-full bg-cyan-500 animate-pulse shadow-[0_0_15px_rgba(6,182,212,0.6)]" }
                        h1 { class: "text-2xl font-bold tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500", "Chronos WebAssembly Node" }
                    }
                    div {
                        class: "flex space-x-4 text-sm font-medium text-slate-400",
                        span { "Status: Active" }
                        span { "Target: wasm32-unknown-unknown" }
                    }
                }
            }

            // Main Content
            main {
                class: "max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 space-y-8",

                // Dashboard Grid
                div {
                    class: "grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6",

                    // Network Card
                    Card {
                        title: "P2P Network",
                        icon: "🌐",
                        content: rsx! {
                            div { class: "text-emerald-400 font-mono text-sm", "{network_status}" }
                            div { class: "mt-4 space-y-2",
                                div { class: "flex justify-between text-xs text-slate-500", span { "Peers" } span { "12" } }
                                div { class: "flex justify-between text-xs text-slate-500", span { "Latency" } span { "45ms" } }
                            }
                        }
                    }

                    // Dataset Card
                    Card {
                        title: "Dataset Ingestion",
                        icon: "📊",
                        content: rsx! {
                            if dataset_loaded() {
                                div { class: "text-cyan-400 font-mono text-sm animate-fade-in", "California Housing (20,640 records)" }
                            } else {
                                div { class: "text-amber-400 font-mono text-sm animate-pulse", "Fetching from remote..." }
                            }
                        }
                    }

                    // Cryptography Card
                    Card {
                        title: "ZK-ML Proofs",
                        icon: "🛡️",
                        content: rsx! {
                            div { class: "text-purple-400 font-mono text-sm", "Groth16 Verifier Ready" }
                            div { class: "mt-4 h-2 bg-slate-800 rounded-full overflow-hidden",
                                div { class: "h-full bg-gradient-to-r from-purple-500 to-fuchsia-500 w-full animate-[progress_2s_ease-in-out_infinite]" }
                            }
                        }
                    }
                }

                // Visualizer Section
                div {
                    class: "bg-slate-800/30 border border-slate-700/50 rounded-2xl p-8 backdrop-blur-sm",
                    h2 { class: "text-xl font-semibold mb-6 flex items-center space-x-2",
                        span { class: "text-blue-400", "⚙️" }
                        span { "TFHE Execution Visualizer" }
                    }
                    div {
                        class: "bg-black/50 rounded-xl p-6 font-mono text-sm text-slate-300 h-64 overflow-y-auto shadow-inner",
                        div { class: "space-y-3",
                            p { "> Initializing PrototypeFhe..." }
                            p { "> Fetching random seed... OK" }
                            p { "> Starting homomorphic matrix-vector multiplication..." }
                            p { class: "text-amber-300 animate-pulse", "> {fhe_status}" }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn Card(title: String, icon: String, content: Element) -> Element {
    rsx! {
        div {
            class: "bg-slate-800/40 border border-slate-700 rounded-xl p-6 hover:bg-slate-800/60 transition-all duration-300 hover:shadow-[0_0_30px_rgba(6,182,212,0.1)] hover:-translate-y-1 group",
            div {
                class: "flex items-center space-x-3 mb-4",
                span { class: "text-2xl group-hover:scale-110 transition-transform duration-300", "{icon}" }
                h3 { class: "text-lg font-medium text-slate-200", "{title}" }
            }
            {content}
        }
    }
}
