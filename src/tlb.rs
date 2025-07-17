use std::cmp::Ordering;
use std::fmt::{Debug, Display, Formatter};
use binrw::{binread, BinRead, BinResult, Endian};
use binrw::io::{Cursor, Read, Seek};
use miniz_oxide::inflate::decompress_to_vec_zlib;

#[derive(Debug, Clone)]
#[binread]
#[br(big, magic = b"#UT")]
pub struct Ticket {
    pub version: FixedLengthStringNumber<2>,
    pub security_provider_rics: FixedLengthStringStripSpaceZero<4>,
    pub security_provider_key_id: FixedLengthStringStripSpaceZero<5>,
    #[br(args(version.0))]
    pub signature: TicketSignature,
    #[allow(dead_code)]
    payload_length: FixedLengthStringNumber<4>,
    #[br(parse_with = parse_payload_tlv, args(payload_length.0))]
    pub records: Vec<super::tlb_records::Record>,
}

#[derive(Debug, Clone)]
#[binread]
#[br(import(version: usize))]
pub enum TicketSignature {
    #[br(assert(version == 1, "ASN1Signature requires version == 01"))]
    ASN1Signature([u8; 50]),
    #[br(assert(version == 2, "RawSignature requires version == 02"))]
    RawSignature([u8; 64]),
}

#[derive(Debug, Clone)]
#[binread]
#[br(assert(record_length >= 12))]
struct TicketRecord {
    #[allow(dead_code)]
    record_id: FixedLengthStringStripSpace<6>,
    #[allow(dead_code)]
    record_version: FixedLengthStringStripSpaceZero<2>,
    #[allow(dead_code)]
    record_length: FixedLengthStringNumber<4>,
    #[br(args(&record_id, &record_version, *record_length))]
    record_data: super::tlb_records::Record,
}

#[binrw::parser(reader, endian)]
fn parse_payload_tlv(payload_length: usize) -> BinResult<Vec<super::tlb_records::Record>> {
    let pos = reader.stream_position()?;

    let mut tlvs = Vec::new();

    let payload_data: Vec<u8> = <_>::read_options(reader, endian, binrw::VecArgs {
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
        let t: TicketRecord = <_>::read_options(&mut payload_cursor, endian, ())?;
        tlvs.push(t.record_data);
    }

    Ok(tlvs)
}

fn trim_bytes<'a>(bytes: &'a[u8], trim: &[u8]) -> &'a [u8] {
    let mut offset = 0;
    for b in bytes {
        if trim.contains(b) {
            offset += 1
        } else {
            break
        }
    }
    &bytes[offset..]
}

macro_rules! fixed_length_string {
    ($name:ident, $strip:literal) => {
        #[derive(Clone)]
        pub struct $name<const N: usize>(Vec<u8>);

        impl<const N: usize> binrw::BinRead<> for $name<N> {
            type Args<'a> = ();

            fn read_options<R: Read + Seek>(reader: &mut R, endian: Endian, args: Self::Args<'_>) -> BinResult<Self> {
                let data = <[u8; N]>::read_options(reader, endian, args)?;
                let data = trim_bytes(&data, $strip).to_vec();
                Ok($name(data))
            }
        }

        impl<const N: usize> std::ops::Deref for $name<N> {
            type Target = [u8];

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<const N: usize> PartialEq<str> for $name<N> {
            fn eq(&self, other: &str) -> bool {
                self.0 == other.as_bytes()
            }
        }

        impl<const N: usize> PartialEq<&str> for $name<N> {
            fn eq(&self, other: &&str) -> bool {
                self.0 == other.as_bytes()
            }
        }

        impl<const N: usize> Display for $name<N> {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", String::from_utf8_lossy(&self.0))
            }
        }

        impl<const N: usize> Debug for $name<N> {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", String::from_utf8_lossy(&self.0))
            }
        }
    };
}

fixed_length_string!(FixedLengthString, b"");
fixed_length_string!(FixedLengthStringStripSpace, b" ");
fixed_length_string!(FixedLengthStringStripSpaceZero, b" 0");

#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord)]
pub struct FixedLengthStringNumber<const N: usize>(usize);

impl<const N: usize> Into<usize> for FixedLengthStringNumber<N> {
    fn into(self) -> usize {
        self.0
    }
}

impl<const N: usize> AsRef<usize> for FixedLengthStringNumber<N> {
    fn as_ref(&self) -> &usize {
        &self.0
    }
}

impl<const N: usize> std::ops::Deref for FixedLengthStringNumber<N> {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> PartialEq<usize> for FixedLengthStringNumber<N> {
    fn eq(&self, other: &usize) -> bool {
        &self.0 == other
    }
}

impl<const N: usize> PartialOrd<usize> for FixedLengthStringNumber<N> {
    fn partial_cmp(&self, other: &usize) -> Option<Ordering> {
        self.0.partial_cmp(other)
    }
}

impl<const N: usize> Display for FixedLengthStringNumber<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<const N: usize> Debug for FixedLengthStringNumber<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<const N: usize> BinRead for FixedLengthStringNumber<N> {
    type Args<'a> = ();

    fn read_options<R: Read + Seek>(reader: &mut R, endian: Endian, _args: Self::Args<'_>) -> BinResult<Self> {
        let pos = reader.stream_position()?;
        let l_str: FixedLengthString<N> = <_>::read_options(reader, endian, ())?;
        let l_str = l_str.to_string();
        let b_str = l_str.trim();
        let num: usize = b_str.parse()
            .map_err(|e| binrw::Error::AssertFail {
                pos,
                message: format!("unable to parse {b_str} as number for payload length: {e}"),
            })?;
        Ok(Self(num))
    }
}