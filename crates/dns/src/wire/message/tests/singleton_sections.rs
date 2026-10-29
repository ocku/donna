use super::super::{decode_many, decode_many_with};
use crate::wire::Decoder;

fn byte(reader: &mut Decoder<'_>) -> crate::wire::Result<u8> {
    reader.read_u8()
}

#[test]
fn single_section_uses_one_slot_while_empty_and_multiple_keep_original_results() {
    for count in [0, 1, 2, 4, 5, 65535] {
        for bytes in [vec![], vec![1], vec![1, 2], vec![1, 2, 3, 4, 5]] {
            let mut original = Decoder::new(&bytes);
            let reference: crate::wire::Result<Vec<u8>> =
                (0..count).map(|_| original.read_u8()).collect();
            let mut current = Decoder::new(&bytes);
            let actual = decode_many(&mut current, count, byte);
            assert_eq!(format!("{actual:?}"), format!("{reference:?}"));
            assert_eq!(current.position(), original.position());
            if let Ok(values) = actual
                && count <= 1
            {
                assert_eq!(values.capacity(), usize::from(count));
            }
            let mut contextual = Decoder::new(&bytes);
            let mut calls = 0;
            let result = decode_many_with(&mut contextual, count, |reader| {
                calls += 1;
                reader.read_u8()
            });
            assert_eq!(format!("{result:?}"), format!("{reference:?}"));
            assert_eq!(contextual.position(), original.position());
            assert_eq!(calls, usize::from(count).min(bytes.len() + 1));
        }
    }
}
