use super::*;

/// Bounded duplicate-question suppression window.
pub struct MdnsDuplicateQuestionCache {
    capacity: usize,
    entries: Vec<DuplicateQuestion>,
}

struct DuplicateQuestion {
    name: Box<[u8]>,
    qtype: u16,
    qclass: u16,
    expires_at: Instant,
}

impl MdnsDuplicateQuestionCache {
    /// Creates a cache for recently observed multicast questions.
    pub const fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Vec::new(),
        }
    }

    /// Records a question and reports whether it was already seen during the
    /// one-second duplicate-suppression window.
    pub fn observe(&mut self, question: &Question, now: Instant) -> bool {
        self.entries.retain(|entry| entry.expires_at > now);
        let name = packed_name(&question.qname);
        if self.entries.iter().any(|entry| {
            entry.name == name
                && entry.qtype == question.qtype.value()
                && entry.qclass == question.qclass.value()
        }) {
            return true;
        }
        if self.capacity == 0 {
            return false;
        }
        if self.entries.len() == self.capacity {
            let victim = self
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(index, _)| index)
                .expect("a full duplicate-question cache contains an entry");
            self.entries.swap_remove(victim);
        }
        self.entries.push(DuplicateQuestion {
            name,
            qtype: question.qtype.value(),
            qclass: question.qclass.value(),
            expires_at: now.checked_add(Duration::from_secs(1)).unwrap_or(now),
        });
        false
    }
}

fn packed_name(name: &crate::DomainName) -> Box<[u8]> {
    let mut output = Vec::with_capacity(name.wire_len());
    for label in name.as_ref() {
        output.push(label.len() as u8);
        output.extend(label.iter().map(u8::to_ascii_lowercase));
    }
    output.push(0);
    output.into_boxed_slice()
}
