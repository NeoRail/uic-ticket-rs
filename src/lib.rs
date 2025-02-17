#[warn(clippy::alloc_instead_of_core)]
#[warn(clippy::std_instead_of_alloc)]
#[warn(clippy::std_instead_of_core)]

use core::fmt::Debug;
use binrw::io::Cursor;
use binrw::{binread, BinRead, BinResult, VecArgs};
use miniz_oxide::inflate::decompress_to_vec_zlib;
use modular_bitfield::bitfield;
use modular_bitfield::prelude::B5;
use crate::helpers::{EditionTime, FixedLengthString, FixedLengthStringNumber, LengthPrefixedString};

mod helpers;


#[derive(Debug, Clone)]
#[binread]
#[br(import(version: usize))]
pub enum TicketSignature {
    #[br(assert(version == 1, "ASN1Signature requires version == 01"))]
    ASN1Signature([u8; 50]),
    #[br(assert(version == 2, "RawSignature requires version == 02"))]
    RawSignature([u8; 64]),
}

#[binrw::parser(reader, endian)]
fn parse_payload_tlv(payload_length: usize) -> BinResult<Vec<TicketTLV>> {
    let pos = reader.stream_position()?;

    let mut tlvs = Vec::new();

    let payload_data: Vec<u8> = <_>::read_options(reader, endian, VecArgs {
        count: payload_length,
        inner: (),
    })?;

    let payload_data = decompress_to_vec_zlib(&payload_data)
        .map_err(|e| {
            binrw::Error::Custom {
                pos,
                err: Box::new(e),
            }
        })?;

    let total_payload_data = payload_data.len();
    let mut payload_cursor = Cursor::new(payload_data);

    while payload_cursor.position() + 8 < total_payload_data as u64 {
        let t: TicketTLV = <_>::read_options(&mut payload_cursor, endian, ())?;
        tlvs.push(t);
    }

    Ok(tlvs)
}


#[derive(Debug, Clone)]
#[binread]
#[br(magic = b"#UT")]
pub struct Ticket {
    pub version: FixedLengthStringNumber<2>,
    pub security_provider_rics: FixedLengthString<4>,
    pub security_provider_key_id: FixedLengthString<5>,
    #[br(args(version.0))]
    pub signature: TicketSignature,
    pub payload_length: FixedLengthStringNumber<4>,
    #[br(parse_with = parse_payload_tlv, args(payload_length.0))]
    pub payload: Vec<TicketTLV>,
}

#[derive(Debug, Clone)]
#[binread]
pub struct TicketTLV {
    pub record_id: FixedLengthString<6>,
    pub record_version: FixedLengthString<2>,
    pub record_length: FixedLengthStringNumber<4>,
    #[br(args(record_id.to_string(), record_length.0))]
    pub record_data: TicketTLVRecord,
}

#[bitfield]
#[derive(BinRead, Debug, Clone)]
#[br(map = Self::from_bytes)]
pub struct UHeadFlags {
    pub international_ticket: bool,
    pub edited_by_agent: bool,
    pub specimen: bool,
    #[allow(non_snake_case)]
    _unused: B5,
}


#[bitfield]
#[derive(BinRead, Debug, Clone)]
#[br(map = Self::from_bytes)]
pub struct TlayFieldFormatting {
    pub bold: bool,
    pub italic: bool,
    pub small: bool,
    #[allow(non_snake_case)]
    _unused: B5,
}

#[derive(Debug, Clone)]
#[binread]
pub struct TLayField {
    pub line: FixedLengthStringNumber<2>,
    pub column: FixedLengthStringNumber<2>,
    pub height: FixedLengthStringNumber<2>,
    pub width: FixedLengthStringNumber<2>,
    pub format: TlayFieldFormatting,
    pub text: LengthPrefixedString,
}

#[derive(Debug, Clone)]
#[binread]
#[br(import(record_id: String, record_length: usize))]
pub enum TicketTLVRecord {
    #[br(assert(record_id == "U_HEAD", "Only U_HEAD record can be parsed as U_HEAD"))]
    UHead {
        distributor_rics: FixedLengthString<4>,
        ticket_key: FixedLengthString<20>,
        edition_time: EditionTime,
        flags: UHeadFlags,
        language: FixedLengthString<2>,
        second_language: FixedLengthString<2>,
    },
    #[br(assert(record_id == "U_TLAY", "Only U_TLAY record can be parsed as U_TLAY"))]
    UTlay {
        layout_standard: FixedLengthString<4>,
        number_of_fields: FixedLengthStringNumber<4>,
        #[br(count = number_of_fields.0)]
        fields: Vec<TLayField>,
    },
    #[br(assert(record_id == "U_FLEX", "Only U_FLEX record can be parsed as U_FLEX"))]
    UFlex {
        #[br(count = record_length - 12)]
        data: Vec<u8>,
    },
    Unknown {
        #[br(count = record_length - 12)]
        data: Vec<u8>,
    },
}
