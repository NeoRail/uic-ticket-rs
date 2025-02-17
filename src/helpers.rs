use std::fmt::{Debug, Display, Formatter};
use binrw::io::{Read, Seek};
use binrw::{binread, BinRead, BinResult, Endian, VecArgs};
use chrono::NaiveDateTime;

#[derive(Clone, Copy)]
#[binread]
pub struct FixedLengthString<const N: usize>([u8; N]);

impl<const N: usize> Display for FixedLengthString<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}


impl<const N: usize> Debug for FixedLengthString<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}

#[derive(Clone, Copy)]
pub struct FixedLengthStringNumber<const N: usize>(pub usize);

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

#[derive(Clone)]
pub struct EditionTime(NaiveDateTime);

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
        let length : FixedLengthStringNumber<4> = <_>::read_options(reader, endian, ())?;
        let data: Vec<u8> = <_>::read_options(reader, endian, VecArgs {
            count: length.0,
            inner: (),
        })?;
        let s = String::from_utf8_lossy(&data).to_string();
        Ok(Self(s))
    }
}
