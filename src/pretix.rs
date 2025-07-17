use binrw::{BinRead, BinResult};

#[binrw::parser(reader, endian)]
pub(crate) fn parse_pretix_ticket_tlv(record_length: usize) -> BinResult<crate::asn1::asn_module_pretix::PretixTicket> {
    let pos = reader.stream_position()?;

    let data: Vec<u8> = <_>::read_options(reader, endian, binrw::VecArgs {
        count: record_length,
        inner: (),
    })?;

    let data = rasn::uper::decode(&data).map_err(|e| binrw::Error::Custom {
        pos,
        err: Box::new(e)
    })?;

    Ok(data)
}