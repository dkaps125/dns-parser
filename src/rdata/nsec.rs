#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Record;

impl<'a> super::Record<'a> for Record {

    const TYPE: isize = 47;

    fn parse(_rdata: &'a [u8], _original: &'a [u8]) -> super::RDataResult<'a> {
        unimplemented!();
    }

    fn length(&self) -> u16 {
        unimplemented!();
    }

    fn to_bytes(&self) -> Vec<u8> {
        unimplemented!();
    }
}
