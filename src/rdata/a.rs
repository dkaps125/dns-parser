use std::net::Ipv4Addr;

use Error;
use byteorder::{BigEndian, ByteOrder};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Record(pub Ipv4Addr);

impl<'a> super::Record<'a> for Record {

    const TYPE: isize = 1;

    fn parse(rdata: &'a [u8], _original: &'a [u8]) -> super::RDataResult<'a> {
        if rdata.len() != 4 {
            return Err(Error::WrongRdataLength);
        }
        let address = Ipv4Addr::from(BigEndian::read_u32(rdata));
        let record = Record(address);
        Ok(super::RData::A(record))
    }

    fn length(&self) -> u16 {
        4
    }

    fn to_bytes(&self) -> Vec<u8> {
        let num: u32 = self.0.into();
        num.to_be_bytes().to_vec()
    }
}

#[cfg(test)]
mod test {

    use RData;
    use super::*;

    #[test]
    fn format() {
        let ip = String::from("128.8.255.16");
        let record = RData::A(super::Record(ip.parse::<Ipv4Addr>().unwrap()));

        assert_eq!(record.rdata_length(), 4);
        assert_eq!(record.to_bytes(), b"\x80\x08\xFF\x10")
    }
}
