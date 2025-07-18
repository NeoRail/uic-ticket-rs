use binrw::BinRead;

mod dosipas;
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
}

#[derive(Debug)]
pub enum Error {
    UnknownBarcodeType,
    InvalidFormat(Box<dyn binrw::error::CustomError>),
    CryptographyError(botan::Error),
}

impl From<rasn::error::DecodeError> for Error {
    fn from(e: rasn::error::DecodeError) -> Self {
        Error::InvalidFormat(Box::new(e))
    }
}

impl From<botan::Error> for Error {
    fn from(e: botan::Error) -> Self {
        Error::CryptographyError(e)
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

mod test {
    use crate::sig;

    const DSA_PUBLIC_KEY: &'static str = "-----BEGIN PUBLIC KEY-----
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

    #[test]
    fn test_decode_pretix_tlb() {
        use num_traits::cast::ToPrimitive;

        let mut pk_db = sig::PublicKeyDB::new();
        pk_db.load_key_pem("5101", "1", DSA_PUBLIC_KEY).unwrap();

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
        assert_eq!(pretix.event_id.to_usize().unwrap(), 1);
        assert_eq!(pretix.item_id.to_usize().unwrap(), 1);
        assert!(pretix.subevent_id.is_none());
        assert!(pretix.variation_id.is_none());
        assert_eq!(pretix.attendee_name.as_ref().unwrap().as_str(), "Q Misell");
    }

    #[test]
    fn test_decode_pretix_dosipas() {
        use num_traits::cast::ToPrimitive;

        let mut pk_db = sig::PublicKeyDB::new();
        pk_db.load_key_pem("5101", "1", DSA_PUBLIC_KEY).unwrap();

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
        assert_eq!(pretix.event_id.to_usize().unwrap(), 1);
        assert_eq!(pretix.item_id.to_usize().unwrap(), 1);
        assert!(pretix.subevent_id.is_none());
        assert!(pretix.variation_id.is_none());
        assert_eq!(pretix.attendee_name.as_ref().unwrap().as_str(), "Q Misell");
    }
}
