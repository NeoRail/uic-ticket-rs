use binrw::{BinRead, BinResult};

#[derive(Debug, Clone)]
pub enum FlexData {
    V1_3(crate::asn1::asn_module_rail_ticket_data_v13::UicRailTicketData),
    V2(crate::asn1::asn_module_rail_ticket_data_v2::UicRailTicketData),
    V3(crate::asn1::asn_module_rail_ticket_data_v2::UicRailTicketData),
}

enum FlexVersion {
    V1_3,
    V2,
    V3
}

#[binrw::parser(reader, endian)]
pub(crate) fn parse_flex_tlv(record_version: &[u8], record_length: usize) -> BinResult<FlexData> {
    let pos = reader.stream_position()?;

    let version = match record_version {
        b"13" => FlexVersion::V1_3,
        b"02" => FlexVersion::V2,
        b"03" => FlexVersion::V3,
        _ => return Err(binrw::Error::NoVariantMatch {
            pos,
        })
    };

    let flex_data: Vec<u8> = <_>::read_options(reader, endian, binrw::VecArgs {
        count: record_length,
        inner: (),
    })?;

    let data = parse_flex(version, &flex_data).map_err(|e| binrw::Error::Custom {
        pos,
        err: Box::new(e)
    })?;

    Ok(data)
}

fn parse_flex(version: FlexVersion, data: &[u8]) -> Result<FlexData, rasn::error::DecodeError> {
    match version {
        FlexVersion::V1_3 => Ok(FlexData::V1_3(rasn::uper::decode(data)?)),
        FlexVersion::V2 => Ok(FlexData::V2(rasn::uper::decode(data)?)),
        FlexVersion::V3 => Ok(FlexData::V3(rasn::uper::decode(data)?)),
    }
}