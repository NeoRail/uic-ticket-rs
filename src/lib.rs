use binrw::BinRead;

pub mod dosipas;
pub mod flex;
pub mod pretix;
pub mod sig;
#[warn(clippy::alloc_instead_of_core)]
#[warn(clippy::std_instead_of_alloc)]
#[warn(clippy::std_instead_of_core)]
pub mod tlb;
pub mod tlb_records;

pub mod asn1 {
    include!("../asn1_gen/rail_ticket_data_v1_3_5.rs");
    include!("../asn1_gen/rail_ticket_data_v2_0_3.rs");
    include!("../asn1_gen/rail_ticket_data_v3_0_5.rs");
    include!("../asn1_gen/barcode_header_v1_0_0.rs");
    include!("../asn1_gen/barcode_header_v2_0_1.rs");
    include!("../asn1_gen/dynamic_content_data_v1_0_5.rs");
    include!("../asn1_gen/fr_intercode_v1.rs");
    include!("../asn1_gen/sncf_transport_v1.rs");
    include!("../asn1_gen/uicPretix_v1.rs");
    include!("../asn1_gen/pretixWallet_v1.rs");
}

#[derive(Debug)]
pub enum Error {
    UnknownBarcodeType,
    InvalidFormat(Box<dyn binrw::error::CustomError>),
    CryptographyError(Box<dyn std::error::Error>),
    UnsupportedData(String)
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::UnknownBarcodeType => write!(f, "unknown barcode type"),
            Self::InvalidFormat(e) => write!(f, "invalid barcode format: {}", e),
            Self::CryptographyError(e) => write!(f, "cryptography error: {}", e),
            Self::UnsupportedData(e) => write!(f, "unsupported data: {}", e),
        }
    }
}

impl From<rasn::error::DecodeError> for Error {
    fn from(e: rasn::error::DecodeError) -> Self {
        Error::InvalidFormat(Box::new(e))
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Ticket {
    UicTlbTicket(tlb::Ticket),
    UicDosipasTicket(dosipas::DosipasTicket),
}

impl Ticket {
    pub fn parse(data: &[u8]) -> Result<Ticket, Error> {
        if data.len() >= 3 && &data[0..3] == b"#UT" {
            match tlb::Ticket::read(&mut binrw::io::Cursor::new(data)) {
                Ok(ticket) => Ok(Ticket::UicTlbTicket(ticket)),
                Err(err) => Err(Error::InvalidFormat(Box::new(err))),
            }
        } else if let Ok(data) =
            rasn::uper::decode::<asn1::asn_module_header_v2::UicBarcodeHeader>(data)
        {
            dosipas::DosipasTicket::try_from(data).map(Ticket::UicDosipasTicket)
        } else if let Ok(data) =
            rasn::uper::decode::<asn1::asn_module_header_v1::UicBarcodeHeader>(data)
        {
            dosipas::DosipasTicket::try_from(data).map(Ticket::UicDosipasTicket)
        } else {
            Err(Error::UnknownBarcodeType)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::sig;

    const GLAUCA_PUBLIC_KEY: &'static str = "-----BEGIN PUBLIC KEY-----
MIIBvzCCATMGByqGSM44BAEwggEmAoGBANudcKJHbCxGh7Bm9j55Cpp6OcfUpUJQ
YZTcnSb0Zrc72Wq/tgXoJ/OFmsgyxgwWtjhg8J94rrLersfGUJejjahebXhB6kv0
gfyJw1DyD9vtnpJejI9vxg6+BL1vc82yItCNAEFzqXZylZK58NceES+CHng3Dso6
zZLUSTV+Ieq/Ah0AjaMThCPlD00bEhNXp1Maafe0dYhPgJ+DqigAxQKBgBnb6+GK
xgzil/ABMhRy0D19sFu+AlD3+ybLp1zLecpvwljaE0XDNpPRAK0fXu87oqzvD2dI
qgijIwjE9wwr8lv8XL8E4w67nGO2p1pLpV2fUQHDjBadomsAURpRB1GHEMq1LgGm
x+N3Ov27BCHEiII/JvmxvmHt3D7tBt20t7U/A4GFAAKBgQCZfpkvmoiGw30VK6jz
1x01BOXj3TP4RMynMvhemQ9FRO35KnrJ9CQiNGFK4av9Qw6Nw6sQkgCwFPqhv49D
FKOUQzCrZagvkQhbIhjWWxF3CGxZ0AxGY+XsdZbPjfVrIemwm8m4BaZnPMTyq4Q8
HbttD0ltz0MC2+YIDXxHSVvAjQ==
-----END PUBLIC KEY-----";

    const GRAND_EST_PUBLIC_KEY: &'static str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEe5B0vss2A37sR74bKDPppZwVZJMD
85SvXmhCErP/LiELKL2UzPG9IR4MegX6eDdYhd1Dp7u1DjzEoqIKHMjvpg==
-----END PUBLIC KEY-----";

    #[test]
    fn test_decode_pretix_tlb() {
        use num_traits::cast::ToPrimitive;

        let mut pk_db = sig::PublicKeyDB::new();
        pk_db.load_key_pem("5101", "1", GLAUCA_PUBLIC_KEY).unwrap();

        let data = hex_literal::hex!("235554303235313031303030303100000000336eb61a6ab9591402bc6c78fba34bbbff70f079f6adf93ec1798a910000000041a2492135f04f4cbe40af72f39b3c448bca115434b1085f8ac7271e30303436789c333534300c883030343030b61460b23fd55af73f7a9aeba1f0cd0c2c40a0e8d268baf4ecd48d1b00e54f0d4f");
        let ticket = super::Ticket::parse(&data).unwrap();

        pk_db.verify_ticket(&ticket).unwrap();

        let ticket = match ticket {
            super::Ticket::UicTlbTicket(ticket) => ticket,
            _ => unreachable!(),
        };

        assert_eq!(ticket.version, 2);
        assert_eq!(ticket.security_provider_rics, "5101");
        assert_eq!(ticket.security_provider_key_id, "1");
        assert_eq!(ticket.records.len(), 1);
        let pretix = match &ticket.records[0] {
            super::tlb_records::Record::PretixTicket(c) => c,
            _ => unreachable!(),
        };
        assert_eq!(pretix.order_year, 2025);
        assert_eq!(pretix.order_day, 190);
        assert_eq!(pretix.order_time, 1216);
        assert_eq!(pretix.event_slug, "\u{1}");
        assert_eq!(pretix.item_id.to_usize().unwrap(), 1);
        assert!(pretix.subevent_id.is_none());
        assert!(pretix.variation_id.is_none());
        assert_eq!(pretix.attendee_name.as_ref().unwrap().as_str(), "Q Misell");
    }

    #[test]
    fn test_decode_pretix_dosipas() {
        use num_traits::cast::ToPrimitive;

        let mut pk_db = sig::PublicKeyDB::new();
        pk_db.load_key_pem("5101", "1", GLAUCA_PUBLIC_KEY).unwrap();

        let data = hex_literal::hex!("0155655a013ec00008084df6ac5831a1524d81b10023d9e091e0341888f8257b3000404040421448135a5cd95b1b0072a8648ce380401096086480165030403023e303c021c369b48928fbf9e186be758f0134e437914bc87f3903ea8410a340a79021c2d3ec4b97854b9c0e73dd5d5a2e75281b0eac593447ccbe0b9cf68220");
        let ticket = super::Ticket::parse(&data).unwrap();

        pk_db.verify_ticket(&ticket).unwrap();

        let ticket = match ticket {
            super::Ticket::UicDosipasTicket(ticket) => ticket,
            _ => unreachable!(),
        };

        assert_eq!(ticket.security_provider, "5101");
        assert_eq!(ticket.key_id, 1);
        assert!(ticket.end_of_validity.is_none());
        assert!(ticket.validity_duration.is_none());
        assert!(ticket.level2_data.is_none());
        assert!(!ticket.has_level2_signature());
        assert_eq!(ticket.records.len(), 1);
        let pretix = match &ticket.records[0] {
            super::dosipas::Record::PretixTicket(c) => c,
            _ => unreachable!(),
        };
        assert_eq!(pretix.order_year, 2025);
        assert_eq!(pretix.order_day, 190);
        assert_eq!(pretix.order_time, 1216);
        assert_eq!(pretix.event_slug, "\u{1}");
        assert_eq!(pretix.item_id.to_usize().unwrap(), 1);
        assert!(pretix.subevent_id.is_none());
        assert!(pretix.variation_id.is_none());
        assert_eq!(pretix.attendee_name.as_ref().unwrap().as_str(), "Q Misell");
    }

    #[test]
    fn test_decode_sncf_dosipas_l2() {
        let mut pk_db = sig::PublicKeyDB::new();
        pk_db.load_key_pem("3703", "5", GRAND_EST_PUBLIC_KEY).unwrap();

        let data = hex_literal::hex!("815565dff8e76000280824687099c053390101cec1237a9a4195c6a5264b13449250915fc404810000408049caeb315cd9732bf932b8c4e1be4c8b5ae5ccc96b468df2ad72c1c635b972b36ce32b772cb2b9ca00014121b1ca2221b18219816a1a29a1b169a19232216a0a12198969a191b99a0a2a199209ca2a10950012c224806719e006451f80c024010064a0123624056241003500010018008004000228298a68240a098aaa640646890408a9aa6081110a000004154324671e81808384154324671e81808384154324671e82018104154324671e82018110819654667f681c5d847d5856b62585c948aa7a1865e4034cfc3a2b2a0b722c2694848e2a6895a3982281100e01b91fbef6834f30dcfc027fd79183fe3233e7fffb206757e06b1c9c7924ce8110807224fc8952f20d4c8c41c2b01b1debcb8ebfb39886449631bb9792df94249f100246890d88cb02d8f7ed5d0ea535d0ea538997b65d9bf86dcbbba0e0ea4402398228110804fb2eeb3d4b9e3521b6c775fc7340e2a4d4a649125067a67c1e46924f73d7c94011033f5dbdafba027ee8314ccf97c5c86dd075fc5c001baf7a53a3f1622c6d00e1e8");
        let ticket = super::Ticket::parse(&data).unwrap();

        pk_db.verify_ticket(&ticket).unwrap();

        let ticket = match ticket {
            super::Ticket::UicDosipasTicket(ticket) => ticket,
            _ => unreachable!(),
        };

        assert_eq!(ticket.security_provider, "3703");
        assert_eq!(ticket.key_id, 5);
        assert!(ticket.end_of_validity.is_some());
        assert_eq!(ticket.validity_duration.unwrap().as_seconds_f64(), 300.0);

        let l2_data = match ticket.level2_data {
            Some(super::dosipas::Level2Data::DynamicContentData(ref dcd)) => dcd,
            _ => unreachable!(),
        };
        assert!(l2_data.dynamic_content_time_stamp.is_some());
        assert!(ticket.has_level2_signature());

        assert_eq!(ticket.records.len(), 1);
        let pretix = match &ticket.records[0] {
            super::dosipas::Record::Flex(c) => c,
            _ => unreachable!(),
        };
    }
}
