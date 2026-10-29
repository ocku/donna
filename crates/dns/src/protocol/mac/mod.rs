//! Bridges existing RustCrypto HMAC (digest 0.10) to SHA-2 (digest 0.11).
//! Only trait forwarding: all hashing, padding, key processing and constant-time
//! verification remain in RustCrypto. SHA-2 0.11 retains runtime ARM acceleration.
//! Block/output sizes come from the hash's own associated types.
use hmac::digest::{
    FixedOutput, HashMarker, Output, OutputSizeUser, Update, crypto_common::BlockSizeUser,
};

#[derive(Clone, Default)]
pub(super) struct CompatibleSha256(sha2::Sha256);
impl OutputSizeUser for CompatibleSha256 {
    type OutputSize = <sha2::Sha256 as sha2::digest::OutputSizeUser>::OutputSize;
}
impl BlockSizeUser for CompatibleSha256 {
    type BlockSize = <sha2::Sha256 as sha2::digest::common::BlockSizeUser>::BlockSize;
}
impl HashMarker for CompatibleSha256 {}
impl Update for CompatibleSha256 {
    fn update(&mut self, input: &[u8]) {
        sha2::Digest::update(&mut self.0, input);
    }
}
impl FixedOutput for CompatibleSha256 {
    fn finalize_into(self, output: &mut Output<Self>) {
        output.copy_from_slice(&sha2::Digest::finalize(self.0));
    }
}
pub(super) type Sha256Mac = hmac::SimpleHmac<CompatibleSha256>;

#[cfg(test)]
mod tests;
