use byteorder::{ByteOrder, BigEndian, WriteBytesExt};

use {Opcode, ResponseCode, Header, QueryType, QueryClass, Name, Class, RData};
use {ResourceRecord};

#[derive(Debug)]
#[allow(missing_docs)]  // should be covered by spec
struct Question<'a> {
    pub qname: &'a str,
    /// Whether or not we prefer unicast responses.
    /// This is used in multicast DNS.
    pub prefer_unicast: bool,
    pub qtype: QueryType,
    pub qclass: QueryClass,
}

/// Allows to build a DNS packet
///
/// Both query and answer packets may be built with this interface, although,
/// much of functionality is not implemented yet.
#[derive(Debug)]
pub struct Builder<'a> {
    head: Header,
    questions: Vec<Question<'a>>,
    answers: Vec<ResourceRecord<'a>>,
    nameservers: Vec<ResourceRecord<'a>>,
    additional: Vec<ResourceRecord<'a>>,
}

impl<'a> Builder<'a> {
    /// Builds the builder content into a vector-represented packet
    pub fn build(&self) -> Result<Vec<u8>, Vec<u8>> {
        let mut buf = Vec::with_capacity(512);
        buf.extend([0u8; 12].iter());
        self.head.write(&mut buf[..12]);

        for question in &self.questions {
            Builder::write_name(&mut buf, question.qname);
            buf.write_u16::<BigEndian>(question.qtype as u16).unwrap();
            let prefer_unicast: u16 = if question.prefer_unicast { 0x8000 } else { 0x0000 };
            buf.write_u16::<BigEndian>(question.qclass as u16 | prefer_unicast).unwrap();
        }

        for answer in &self.answers {
            Builder::write_name(&mut buf, &answer.name.to_string());

            let data = &answer.data;
            let type_code = data.type_code();

            buf.write_u16::<BigEndian>(type_code as u16).unwrap();
            buf.write_u16::<BigEndian>(answer.cls as u16).unwrap();
            buf.write_u32::<BigEndian>(answer.ttl).unwrap();
            buf.write_u16::<BigEndian>(answer.data.rdata_length()).unwrap();
            buf.extend(answer.data.to_bytes().iter());
        }

        return Ok(buf)
    }

    /// Creates a new query
    ///
    /// Initially all sections are empty. You're expected to fill
    /// the questions section with `add_question`
    pub fn new(id: u16, recursion: bool) -> Builder<'a> {
        let head = Header {
            id: id,
            query: true,
            opcode: Opcode::StandardQuery,
            authoritative: false,
            truncated: false,
            recursion_desired: recursion,
            recursion_available: false,
            authenticated_data: false,
            checking_disabled: false,
            response_code: ResponseCode::NoError,
            questions: 0,
            answers: 0,
            nameservers: 0,
            additional: 0,
        };
        Builder { 
            head,
            answers: Vec::new(),
            questions: Vec::new(),
            nameservers: Vec::new(),
            additional: Vec::new(),
        }
    }

    /// question adds a new DNS question to this packet
    pub fn question(&mut self, qname: &'a str, prefer_unicast: bool,
        qtype: QueryType, qclass: QueryClass) -> &Builder {
        if self.head.questions == 65535 {
            panic!("Too many questions");
        }

        let question = Question {
            prefer_unicast,
            qname,
            qtype,
            qclass,
        };
        self.questions.push(question);
        self.head.questions += 1;

        self
    }

    /// Appends an answer to the packet
    pub fn answer(&mut self, qname: &'a str, cls: Class, data: RData<'a>, 
        multicast_unique: bool, ttl: u32) -> &Builder {
        let answer = ResourceRecord {
            name: Name::from_string(qname),
            cls,
            data,
            multicast_unique,
            ttl
        };
        self.answers.push(answer);
        self.head.answers += 1;

        self
    }

    fn write_name(buf: &mut Vec<u8>, name: &str) {
        for part in name.split('.') {
            assert!(part.len() < 63);
            let ln = part.len() as u8;
            buf.push(ln);
            buf.extend(part.as_bytes());
        }
        buf.push(0);
    }
}

#[cfg(test)]
mod test {
    use QueryType as QT;
    use QueryClass as QC;
    use super::Builder;

    #[test]
    fn build_query() {
        let mut bld = Builder::new(1573, true);
        bld.question("example.com", false, QT::A, QC::IN);
        let result = b"\x06%\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
                      \x07example\x03com\x00\x00\x01\x00\x01";
        assert_eq!(&bld.build().unwrap()[..], &result[..]);
    }

    #[test]
    fn build_unicast_query() {
        let mut bld = Builder::new(1573, true);
        bld.question("example.com", true, QT::A, QC::IN);
        let result = b"\x06%\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
                      \x07example\x03com\x00\x00\x01\x80\x01";
        assert_eq!(&bld.build().unwrap()[..], &result[..]);
    }

    #[test]
    fn build_srv_query() {
        let mut bld = Builder::new(23513, true);
        bld.question("_xmpp-server._tcp.gmail.com", false, QT::SRV, QC::IN);
        let result = b"[\xd9\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
            \x0c_xmpp-server\x04_tcp\x05gmail\x03com\x00\x00!\x00\x01";
        assert_eq!(&bld.build().unwrap()[..], &result[..]);
    }
}
