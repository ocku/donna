use dns::Message;

use super::{AxfrFrameStatus, AxfrSeriesValidator};

pub(crate) fn valid_axfr_response_series(
    responses: &[Message],
    question: &dns::Question,
    request_questions_are_safe_to_echo: bool,
) -> bool {
    let mut validator = AxfrSeriesValidator::new(
        question.clone(),
        request_questions_are_safe_to_echo,
        super::super::MAX_AXFR_VALIDATION_RRSETS,
    );
    for (index, response) in responses.iter().enumerate() {
        let Some(status) = validator.accept(response) else {
            return false;
        };
        if status == AxfrFrameStatus::Complete && index + 1 != responses.len() {
            return false;
        }
    }
    validator.finish()
}
