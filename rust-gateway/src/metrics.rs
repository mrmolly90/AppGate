use prometheus::Registry;

pub fn init_metrics() -> Registry {
    Registry::new()
}

pub fn gather_metrics() -> String {
    let registry = Registry::new();
    let encoder = prometheus::TextEncoder::new();
    let metric_families = registry.gather();
    encoder.encode_to_string(&metric_families).unwrap_or_default()
}
