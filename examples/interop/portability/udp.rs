//! Packet adapter for the unchanged Linux UDP batch-send implementation.
mod server {
    use std::net::SocketAddr;
    use tokio::{net::UdpSocket, sync::OwnedSemaphorePermit, time};
    pub(super) struct PreparedPacket {
        pub(super) wire: Vec<u8>,
        pub(super) peer: SocketAddr,
        pub(super) deadline: time::Instant,
        _permit: OwnedSemaphorePermit,
    }
    impl PreparedPacket {
        pub(super) fn for_test(
            wire: Vec<u8>,
            peer: SocketAddr,
            deadline: time::Instant,
            permit: OwnedSemaphorePermit,
        ) -> Self {
            Self {
                wire,
                peer,
                deadline,
                _permit: permit,
            }
        }
        pub(super) async fn send(self, socket: &UdpSocket) {
            if self.deadline <= time::Instant::now() {
                return;
            }
            let _ = time::timeout_at(self.deadline, socket.send_to(&self.wire, self.peer)).await;
        }
    }
}
#[path = "../../../crates/transport/src/udp/send.rs"]
mod send;
