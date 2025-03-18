#![allow(invalid_reference_casting)]
pub mod config;
pub mod filters;
pub mod grpc;
pub mod metrics;
pub mod plugin;
pub mod version;

pub fn get_thread_name() -> String {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static ATOMIC_ID: AtomicUsize = AtomicUsize::new(0);
    let id = ATOMIC_ID.fetch_add(1, Ordering::Relaxed);
    format!("solGeyserGrpc{id:02}")
}

pub mod redacted_tcp_memory_pool;
pub mod redacted_tcp_server;
pub mod redacted_tcp_types;
