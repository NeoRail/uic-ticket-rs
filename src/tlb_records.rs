use std::fmt::{Debug, Display, Formatter};
use binrw::{binread, BinRead, BinResult, Endian};
use binrw::io::{Read, Seek};
use chrono::NaiveDateTime;
use modular_bitfield::bitfield;
use modular_bitfield::prelude::B5;
use crate::tlb::{FixedLengthString, FixedLengthStringStripSpace, FixedLengthStringStripSpaceZero, FixedLengthStringNumber};
use crate::flex::{FlexData, parse_flex_tlv};
use crate::pretix::parse_pretix_ticket_tlv;

#[derive(Debug, Clone)]
#[binread]
#[br(import(record_id: &FixedLengthStringStripSpace<6>, record_version: &FixedLengthStringStripSpaceZero<2>, record_length: usize))]
pub enum Record {
    #[br(
        assert(record_id == "U_HEAD", "Only U_HEAD record can be parsed as U_HEAD"),
        assert(record_version == "1", "Only version 1 headers are defined")
    )]
    UHead(Header),
    #[br(
        assert(record_id == "U_TLAY", "Only U_TLAY record can be parsed as U_TLAY"),
        assert(record_version == "1", "Only version 1 ticket layouts are defined")
    )]
    UTlay(Layout),
    #[br(
        assert(record_id == "U_FLEX", "Only U_FLEX record can be parsed as U_FLEX"),
        assert(record_version == "13" || record_version == "2" || record_version == "3", "Invalid flexible data version")
    )]
    UFlex(
        #[br(
            parse_with=parse_flex_tlv,
            args(record_version, record_length - 12)
        )]
        FlexData
    ),
    #[br(
        assert(record_id == "5101PX", "Only Pretix ticket records can be parsed as 5101PX"),
        assert(record_version == "1", "Invalid pretix data version")
    )]
    PretixTicket(
        #[br(
            parse_with=parse_pretix_ticket_tlv,
            args(record_length - 12)
        )]
        crate::asn1::asn_module_pretix::PretixTicket
    ),
    Custom (
        #[br(args(record_id.to_string(), record_version.to_string(), record_length - 12))]
        CustomRecord
    ),
}

#[derive(Debug, Clone)]
#[binread]
pub struct Header {
    pub distributor_rics: FixedLengthStringStripSpaceZero<4>,
    pub ticket_id: FixedLengthStringStripSpace<20>,
    pub edition_time: EditionTime,
    pub flags: HeaderFlags,
    pub language: FixedLengthStringStripSpace<2>,
    pub second_language: FixedLengthStringStripSpace<2>,
}

#[bitfield]
#[derive(BinRead, Debug, Clone)]
#[br(map = Self::from_bytes)]
pub struct HeaderFlags {
    pub international_ticket: bool,
    pub edited_by_agent: bool,
    pub specimen: bool,
    #[allow(non_snake_case)]
    _unused: B5,
}

#[derive(Debug, Clone)]
#[binread]
pub struct Layout {
    pub layout_standard: FixedLengthStringStripSpace<4>,
    #[allow(dead_code)]
    number_of_fields: FixedLengthStringNumber<4>,
    #[br(count = number_of_fields)]
    pub fields: Vec<LayoutField>,
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
pub struct LayoutField {
    pub line: FixedLengthStringNumber<2>,
    pub column: FixedLengthStringNumber<2>,
    pub height: FixedLengthStringNumber<2>,
    pub width: FixedLengthStringNumber<2>,
    pub format: TlayFieldFormatting,
    pub text: LengthPrefixedString,
}

#[derive(Debug, Clone)]
#[binread]
#[br(import(record_id: String, record_version: String, record_length: usize))]
pub struct CustomRecord {
    #[br(calc = record_id)]
    pub record_id: String,
    #[br(calc = record_version)]
    pub record_version: String,
    #[br(count = record_length)]
    pub data: Vec<u8>,
}

#[derive(Clone)]
pub struct EditionTime(NaiveDateTime);

impl std::ops::Deref for EditionTime {
    type Target = NaiveDateTime;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for EditionTime {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Debug for EditionTime {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl BinRead for EditionTime {
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(reader: &mut R, endian: Endian, _args: Self::Args<'_>) -> BinResult<Self> {
        let pos = reader.stream_position()?;
        let l_str: FixedLengthString<12> = <_>::read_options(reader, endian, ())?;
        let l_str = l_str.to_string();
        let t = NaiveDateTime::parse_from_str(&l_str, "%d%m%Y%H%M")
            .map_err(|e| {
                binrw::Error::Custom {
                    pos,
                    err: Box::new(e),
                }
            })?;
        Ok(Self(t))
    }
}

#[derive(Clone)]
pub struct LengthPrefixedString(String);

impl AsRef<str> for LengthPrefixedString {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl std::ops::Deref for LengthPrefixedString {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for LengthPrefixedString {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Debug for LengthPrefixedString {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl BinRead for LengthPrefixedString {
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(reader: &mut R, endian: Endian, _args: Self::Args<'_>) -> BinResult<Self> {
        let length: FixedLengthStringNumber<4> = <_>::read_options(reader, endian, ())?;
        let data: Vec<u8> = <_>::read_options(reader, endian, binrw::VecArgs {
            count: *length,
            inner: (),
        })?;
        let s = String::from_utf8_lossy(&data).to_string();
        Ok(Self(s))
    }
}