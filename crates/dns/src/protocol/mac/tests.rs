use super::*;
use hmac::digest::Digest;

#[test]
fn forwarded_hash_types_and_chunked_outputs_match_library_and_ring() {
    assert_eq!(
        <CompatibleSha256 as OutputSizeUser>::output_size(),
        <sha2::Sha256 as sha2::digest::OutputSizeUser>::output_size()
    );
    assert_eq!(
        <CompatibleSha256 as BlockSizeUser>::block_size(),
        <sha2::Sha256 as sha2::digest::common::BlockSizeUser>::block_size()
    );
    for length in [0, 1, 55, 56, 63, 64, 65, 127, 128, 129, 1232, 65535] {
        let input: Vec<_> = (0..length).map(|i| (i * 131 + 7) as u8).collect();
        let expected = ring::digest::digest(&ring::digest::SHA256, &input);
        for chunk in [1, 63, 64, 65, 1024] {
            let mut hash = CompatibleSha256::default();
            Digest::update(&mut hash, []);
            for part in input.chunks(chunk) {
                Digest::update(&mut hash, part);
            }
            assert_eq!(hash.finalize().as_slice(), expected.as_ref());
        }
    }
}
