use Error;

const SEGMENT_LENGTH: usize = 255;

#[derive(Debug, Clone)]
pub struct Record {
    bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct RecordIter<'a> {
    bytes: &'a [u8],
}

impl<'a> Iterator for RecordIter<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        if self.bytes.len() >= 1 {
            let len = self.bytes[0] as usize;
            debug_assert!(self.bytes.len() >= len+1);
            let (head, tail) = self.bytes[1..].split_at(len);
            self.bytes = tail;
            return Some(head);
        }
        return None;
    }
}

impl Record {

    // Returns iterator over text chunks
    pub fn iter(&self) -> RecordIter {
        RecordIter {
            bytes: &self.bytes,
        }
    }

    pub fn from_str(s: &str) -> Record {
        let mut result: Vec<u8> = Vec::new();
        let bytes = s.as_bytes();
        let byte_len = bytes.len();

        let mut pos = 0;
        while pos < byte_len {
            if byte_len - pos >= 256 {
                result.push(SEGMENT_LENGTH as u8);
                result.extend_from_slice(&bytes[pos..pos+SEGMENT_LENGTH]);
                pos += SEGMENT_LENGTH;
            } else {
                result.push((byte_len - pos) as u8);
                result.extend_from_slice(&bytes[pos..byte_len]);
                pos += byte_len - pos;
            }
        }

        Record{ bytes: result }
    }
}

impl<'a> super::Record<'a> for Record {

    const TYPE: isize = 16;

    fn parse(rdata: &[u8], _original: &[u8]) -> super::RDataResult<'a> {
        // Just a quick check that record is valid
        let len = rdata.len();
        if len < 1 {
            return Err(Error::WrongRdataLength);
        }
        let mut pos = 0;
        while pos < len {
            let rdlen = rdata[pos] as usize;
            pos += 1;
            if len < rdlen + pos {
                return Err(Error::WrongRdataLength);
            }
            pos += rdlen;
        }
        Ok(super::RData::TXT(Record {
            bytes: rdata.to_vec(),
        }))
    }

    fn length(&self) -> u16 {
        self.bytes.len() as u16
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

#[cfg(test)]
mod test {

    use std::str::from_utf8;

    use {Packet, Header};
    use Opcode::*;
    use ResponseCode::NoError;
    use QueryType as QT;
    use QueryClass as QC;
    use Class as C;
    use RData;
    use rdata::Record;

    #[test]
    fn test_from_str() {
        let record = super::Record::from_str("this is a test");
        assert_eq!(record.to_bytes(), b"\x0Ethis is a test")
    }

    #[test]
    fn parse_response_multiple_strings() {
        let response = b"\x06%\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\
                          \x08facebook\x03com\x00\x00\x10\x00\x01\
                          \xc0\x0c\x00\x10\x00\x01\x00\x01\x51\x3d\x00\x23\
                          \x15\x76\x3d\x73\x70\x66\x31\x20\x72\x65\x64\x69\
                          \x72\x65\x63\x74\x3d\x5f\x73\x70\x66\x2e\
                          \x0c\x66\x61\x63\x65\x62\x6f\x6f\x6b\x2e\x63\x6f\x6d";

        let packet = Packet::parse(response).unwrap();
        assert_eq!(packet.header, Header {
            id: 1573,
            query: false,
            opcode: StandardQuery,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: true,
            authenticated_data: false,
            checking_disabled: false,
            response_code: NoError,
            questions: 1,
            answers: 1,
            nameservers: 0,
            additional: 0,
        });
        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.questions[0].qtype, QT::TXT);
        assert_eq!(packet.questions[0].qclass, QC::IN);
        assert_eq!(&packet.questions[0].qname.to_string()[..], "facebook.com");
        assert_eq!(packet.answers.len(), 1);
        assert_eq!(&packet.answers[0].name.to_string()[..], "facebook.com");
        assert_eq!(packet.answers[0].multicast_unique, false);
        assert_eq!(packet.answers[0].cls, C::IN);
        assert_eq!(packet.answers[0].ttl, 86333);
        match packet.answers[0].data {
            RData::TXT(ref text) => {
                assert_eq!(text.iter()
                    .map(|x| from_utf8(x).unwrap())
                    .collect::<Vec<_>>()
                    .concat(), "v=spf1 redirect=_spf.facebook.com");

                // also assert boundaries are kept
                assert_eq!(text.iter().collect::<Vec<_>>(),
                    ["v=spf1 redirect=_spf.".as_bytes(),
                     "facebook.com".as_bytes()]);
            }
            ref x => panic!("Wrong rdata {:?}", x),
        }
    }
}
