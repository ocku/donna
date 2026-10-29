use crate::wire::{Decoder, Result};

mod bitmap;
mod decode;
mod encode;
mod validation;

use bitmap::{decode_type_bitmap, encode_type_bitmap, validate_wks_bitmap};
pub(crate) use decode::decode_rdata;
pub(crate) use encode::{encode_rdata, encode_validated_rdata};
pub(crate) use validation::validation_error_to_wire;

trait CharacterStringReader {
    fn read_character_string(&mut self) -> Result<Vec<u8>>;
}
impl CharacterStringReader for Decoder<'_> {
    fn read_character_string(&mut self) -> Result<Vec<u8>> {
        let length = usize::from(self.read_u8()?);
        Ok(self.read_exact(length)?.to_vec())
    }
}

#[cfg(test)]
mod tests;
