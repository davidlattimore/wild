fn main() {
    if std::env::var("CARGO_FEATURE_PLUGINS").is_ok() {
        cc::Build::new()
            .file("src/plugin_message_shim.c")
            .compile("plugin_message_shim");
    }
}
