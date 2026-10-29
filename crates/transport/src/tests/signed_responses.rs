use dns::{
    ClassType, DomainName, Headers, IntoWire, Message, OpCode, QClassType, QueryType, Question,
    Sig0SigningKey, TsigAlgorithm, TsigErrorCode, TsigKey,
};

use crate::{DnsRequest, DnsRequestHandler};

pub(crate) struct SignedResponse {
    pub request: Message,
    pub response: Message,
    signature: Signature,
}

enum Signature {
    Unsigned,
    Tsig(TsigKey, Vec<u8>),
    Sig0(Sig0SigningKey),
}

impl SignedResponse {
    pub fn cases(id: u16) -> Vec<Self> {
        Self::for_opcode(id, OpCode::Update)
    }

    pub fn inverse_cases(id: u16) -> Vec<Self> {
        Self::for_opcode(id, OpCode::IQuery)
    }

    fn for_opcode(id: u16, opcode: OpCode) -> Vec<Self> {
        let name = DomainName::from_dotted("example.").unwrap();
        let mut request = Message::builder()
            .headers(Headers {
                id,
                opcode,
                ..Headers::default()
            })
            .questions([Question {
                qname: name.clone(),
                qtype: QueryType::SOA,
                qclass: QClassType::Class(ClassType::IN),
            }])
            .build_unchecked();
        if opcode == OpCode::IQuery {
            request.questions.clear();
            request.answers.push(dns::ResourceRecord {
                name: DomainName::root(),
                rtype: dns::RecordType::A,
                class: ClassType::IN,
                ttl: 0,
                rdata: dns::RData::A(std::net::Ipv4Addr::new(192, 0, 2, 1)),
            });
        }
        let mut response = Message::builder()
            .headers(Headers {
                id,
                opcode,
                qr: true,
                ..Headers::default()
            })
            .build_unchecked();
        if opcode == OpCode::IQuery {
            response.questions.push(Question {
                qname: name.clone(),
                qtype: QueryType::A,
                qclass: QClassType::Class(ClassType::IN),
            });
            response.answers.clone_from(&request.answers);
        }
        let unsigned = Self {
            request: request.clone(),
            response: response.clone(),
            signature: Signature::Unsigned,
        };
        if opcode == OpCode::IQuery {
            // IQUERY requests require empty authority and additional sections.
            return vec![unsigned];
        }
        let key = TsigKey::new(name.clone(), TsigAlgorithm::HmacSha256, vec![7; 32]).unwrap();
        let mut tsig_request = request.clone();
        let mac = key.sign_request(&mut tsig_request, 150, 300, None).unwrap();
        let mut tsig_response = response.clone();
        key.sign_response(
            &mut tsig_response,
            &mac,
            id,
            150,
            300,
            TsigErrorCode::NoError,
            vec![],
            None,
        )
        .unwrap();
        const PKCS8: &[u8] = &[
            48, 81, 2, 1, 1, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32, 156, 58, 61, 68, 60, 178,
            171, 104, 83, 159, 96, 163, 246, 190, 164, 46, 68, 164, 64, 34, 239, 214, 158, 122,
            111, 82, 80, 170, 50, 90, 126, 173, 129, 33, 0, 40, 191, 220, 61, 124, 212, 177, 148,
            240, 248, 32, 200, 38, 226, 202, 169, 240, 228, 175, 220, 162, 168, 147, 131, 122, 208,
            184, 21, 228, 15, 161, 31,
        ];
        let sig0_key = Sig0SigningKey::from_ed25519_pkcs8(name, 0, 3, PKCS8).unwrap();
        let mut sig0_request = request;
        sig0_key.sign_request(&mut sig0_request, 100, 200).unwrap();
        let mut sig0_response = response;
        sig0_key
            .sign_response(
                &mut sig0_response,
                &sig0_request.into_wire().unwrap(),
                100,
                200,
            )
            .unwrap();
        vec![
            Self {
                request: tsig_request,
                response: tsig_response,
                signature: Signature::Tsig(key, mac),
            },
            Self {
                request: sig0_request,
                response: sig0_response,
                signature: Signature::Sig0(sig0_key),
            },
        ]
    }

    pub fn handler(&self) -> SignedHandler {
        SignedHandler(self.response.clone())
    }

    pub fn verify(&self, response: &Message) {
        assert!(crate::same_questions(
            &response.questions,
            &self.response.questions
        ));
        let wire = response.into_wire().unwrap();
        assert_eq!(wire, self.response.into_wire().unwrap());
        match &self.signature {
            Signature::Unsigned => {}
            Signature::Tsig(key, mac) => {
                key.verify_response(&wire, mac, 150).unwrap();
            }
            Signature::Sig0(key) => {
                key.verification_key()
                    .verify_response(&wire, &self.request.into_wire().unwrap(), 150)
                    .unwrap();
            }
        }
    }
}

pub(crate) struct SignedHandler(Message);

impl DnsRequestHandler for SignedHandler {
    fn handle<'future>(&'future self, request: DnsRequest) -> crate::BoxFuture<'future, ()> {
        Box::pin(async move {
            assert!(request.respond(self.0.clone()));
        })
    }
}
