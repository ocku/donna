use super::*;

impl Sig0SigningKey {
    /// Signs an IXFR response with explicit outstanding-question context.
    pub fn sign_response_ixfr(
        &self,
        message: &mut Message,
        question: &crate::Question,
        request_wire: &[u8],
        inception: u32,
        expiration: u32,
    ) -> Result<Vec<u8>, Sig0Error> {
        if !message.headers.qr {
            return Err(Sig0Error::WrongDirection);
        }
        self.sign(
            message,
            Some(request_wire),
            inception,
            expiration,
            Some(question),
        )
    }
}
