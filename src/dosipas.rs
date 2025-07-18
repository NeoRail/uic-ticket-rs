use std::convert::TryFrom;
use crate::flex::{parse_flex, FlexVersion};

#[derive(Debug, Clone)]
pub struct DosipasTicket {
    pub security_provider: String,
    pub key_id: u32,
    pub(crate) level1_signed_data: Vec<u8>,
    pub(crate) level2_signed_data: Vec<u8>,
    pub(crate) level1_signature: Vec<u8>,
    pub(crate) level2_signature: Option<Vec<u8>>,
    pub(crate) level1_key_alg: Option<rasn::prelude::ObjectIdentifier>,
    pub(crate) level2_key_alg: Option<rasn::prelude::ObjectIdentifier>,
    pub(crate) level1_signing_alg: Option<rasn::prelude::ObjectIdentifier>,
    pub(crate) level2_signing_alg: Option<rasn::prelude::ObjectIdentifier>,
    pub(crate) level2_public_key: Option<std::sync::Arc<botan::Pubkey>>,
    pub end_of_validity: Option<chrono::DateTime<chrono::Utc>>,
    pub validity_duration: Option<chrono::TimeDelta>,
    pub records: Vec<Record>,
    pub level2_data: Option<Level2Data>,
}

impl DosipasTicket {
    pub fn has_level2_signature(&self) -> bool {
        self.level2_signature.is_some()
    }
}

#[derive(Debug, Clone)]
pub enum Record {
    Flex(crate::flex::FlexData),
    PretixTicket(crate::asn1::asn_module_pretix::PretixTicket),
    Custom(CustomRecord),
}

#[derive(Debug, Clone)]
pub struct CustomRecord {
    record_id: String,
    data: Vec<u8>
}

#[derive(Debug, Clone)]
pub enum Level2Data {
    DynamicContentData(crate::asn1::asn_module_dynamic_content_data_v1::UicDynamicContentData),
    Custom(CustomRecord),
}

impl TryFrom<crate::asn1::asn_module_header_v1::UicBarcodeHeader> for DosipasTicket {
    type Error = crate::Error;
    fn try_from(header: crate::asn1::asn_module_header_v1::UicBarcodeHeader) -> Result<Self, Self::Error> {
        if header.format.as_slice() != b"U1" {
            return Err(crate::Error::UnknownBarcodeType);
        }

        let level2_public_key = match &header.level2_signed_data.level1_data.level2_public_key {
            Some(v) => {
                Some(botan::Pubkey::load_der(v.as_ref())?)
            },
            None => None
        };

        Ok(Self {
            security_provider: if let Some(id) = header.level2_signed_data.level1_data.security_provider_num {
                id.to_string()
            } else if let Some(id) = &header.level2_signed_data.level1_data.security_provider_ia5 {
                id.to_string()
            } else {
                return Err(crate::Error::InvalidFormat(Box::new("One of securityProviderNum or securityProviderIA5 must be set")))
            },
            key_id: header.level2_signed_data.level1_data.key_id.unwrap_or_default(),
            level1_signed_data: rasn::uper::encode(&header.level2_signed_data.level1_data).unwrap(),
            level2_signed_data: rasn::uper::encode(&header.level2_signed_data).unwrap(),
            level1_signature: header.level2_signed_data.level1_signature.unwrap_or_default().to_vec(),
            level2_signature: header.level2_signature.map(|s| s.to_vec()),
            level1_key_alg: header.level2_signed_data.level1_data.level1_key_alg,
            level2_key_alg: header.level2_signed_data.level1_data.level2_key_alg,
            level1_signing_alg: header.level2_signed_data.level1_data.level1_signing_alg,
            level2_signing_alg: header.level2_signed_data.level1_data.level2_signing_alg,
            level2_public_key: level2_public_key.map(std::sync::Arc::new),
            end_of_validity: None,
            validity_duration: None,
            records: header.level2_signed_data.level1_data.data_sequence.into_iter().map(|r| {
                parse_record(r.data_format.to_string(), r.data.as_ref())
            }).collect::<Result<Vec<_>, _>>()?,
            level2_data: header.level2_signed_data.level2_data.map(|r| {
                parse_leve2_data(r.data_format.to_string(), r.data.as_ref())
            }).transpose()?,
        })
    }
}

impl TryFrom<crate::asn1::asn_module_header_v2::UicBarcodeHeader> for DosipasTicket {
    type Error = crate::Error;
    fn try_from(header: crate::asn1::asn_module_header_v2::UicBarcodeHeader) -> Result<Self, Self::Error> {
        if header.format.as_slice() != b"U2" {
            return Err(crate::Error::UnknownBarcodeType);
        }

        let level2_public_key = match &header.level2_signed_data.level1_data.level2_public_key {
            Some(v) => {
                Some(botan::Pubkey::load_der(v.as_ref())?)
            },
            None => None
        };

        let end_of_validity = match (
            &header.level2_signed_data.level1_data.end_of_validity_year,
            &header.level2_signed_data.level1_data.end_of_validity_day,
            &header.level2_signed_data.level1_data.end_of_validity_time
        ) {
            (Some(y), Some(d), Some(t)) => {
                let date = match chrono::NaiveDate::from_yo_opt(*y as i32, *d as u32) {
                    Some(t) => t,
                    None => {
                        return Err(crate::Error::InvalidFormat(Box::new("End of Validity out of range")))
                    }
                };
                let time = match chrono::NaiveTime::from_num_seconds_from_midnight_opt(*t as u32 * 60, 0) {
                    Some(t) => t,
                    None => {
                        return Err(crate::Error::InvalidFormat(Box::new("End of Validity out of range")))
                    }
                };
                Some(date.and_time(time))
            },
            (None, None, None) => None,
            _ => {
                return Err(crate::Error::InvalidFormat(Box::new("End of Validity inconsistently set")))
            }
        };

        let validity_duration = match &header.level2_signed_data.level1_data.validity_duration {
            Some(v) => Some(chrono::TimeDelta::seconds(*v as i64)),
            None => None
        };

        Ok(Self {
            security_provider: if let Some(id) = header.level2_signed_data.level1_data.security_provider_num {
                id.to_string()
            } else if let Some(id) = &header.level2_signed_data.level1_data.security_provider_ia5 {
                id.to_string()
            } else {
                return Err(crate::Error::InvalidFormat(Box::new("One of securityProviderNum or securityProviderIA5 must be set")))
            },
            key_id: header.level2_signed_data.level1_data.key_id.unwrap_or_default(),
            level1_signed_data: rasn::uper::encode(&header.level2_signed_data.level1_data).unwrap(),
            level2_signed_data: rasn::uper::encode(&header.level2_signed_data).unwrap(),
            level1_signature: header.level2_signed_data.level1_signature.unwrap_or_default().to_vec(),
            level2_signature: header.level2_signature.map(|s| s.to_vec()),
            level1_key_alg: header.level2_signed_data.level1_data.level1_key_alg,
            level2_key_alg: header.level2_signed_data.level1_data.level2_key_alg,
            level1_signing_alg: header.level2_signed_data.level1_data.level1_signing_alg,
            level2_signing_alg: header.level2_signed_data.level1_data.level2_signing_alg,
            level2_public_key: level2_public_key.map(std::sync::Arc::new),
            end_of_validity: end_of_validity.map(|t| t.and_utc()),
            validity_duration,
            records: header.level2_signed_data.level1_data.data_sequence.into_iter().map(|r| {
                parse_record(r.data_format.to_string(), r.data.as_ref())
            }).collect::<Result<Vec<_>, _>>()?,
            level2_data: header.level2_signed_data.level2_data.map(|r| {
                parse_leve2_data(r.data_format.to_string(), r.data.as_ref())
            }).transpose()?,
        })
    }
}

fn parse_record(data_format: String, data: &[u8]) -> Result<Record, crate::Error> {
    match data_format.as_str() {
        "FCB1" => Ok(Record::Flex(parse_flex(FlexVersion::V1_3, data)?)),
        "FCB2" => Ok(Record::Flex(parse_flex(FlexVersion::V2, data)?)),
        "FCB3" => Ok(Record::Flex(parse_flex(FlexVersion::V3, data)?)),
        "_5101PTIX" => Ok(Record::PretixTicket(rasn::uper::decode(data)?)),
        _ => Ok(Record::Custom(CustomRecord {
            record_id: data_format,
            data: data.to_vec(),
        }))
    }
}

fn parse_leve2_data(data_format: String, data: &[u8]) -> Result<Level2Data, crate::Error> {
    match data_format.as_str() {
        "FDC1" => Ok(Level2Data::DynamicContentData(rasn::uper::decode(data)?)),
        _ => Ok(Level2Data::Custom(CustomRecord {
            record_id: data_format,
            data: data.to_vec(),
        }))
    }
}