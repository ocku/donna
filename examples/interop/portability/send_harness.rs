//! Isolated harness for the unmodified Donna send.rs on constrained QEMU hosts.

#[cfg(target_os = "linux")]
mod udp;
