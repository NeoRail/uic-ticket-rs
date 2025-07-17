use std::path::PathBuf;
use rasn_compiler::prelude::*;

fn main() {
    println!("cargo:rerun-if-changed=asn1/uicRailTicketData_v1.3.5.asn");
    println!("cargo:rerun-if-changed=asn1/uicRailTicketData_v2.0.3.asn");
    println!("cargo:rerun-if-changed=asn1/uicRailTicketData_v3.0.5.asn");
    println!("cargo:rerun-if-changed=asn1/uicBarcodeHeader_v1.0.0.asn");
    println!("cargo:rerun-if-changed=asn1/uicBarcodeHeader_v2.0.1.asn");
    println!("cargo:rerun-if-changed=asn1/uicDynamicContentData_v1.0.5.asn");
    println!("cargo:rerun-if-changed=asn1/fr_intercode_v1.asn");
    println!("cargo:rerun-if-changed=asn1/sncf_transport_v1.asn");
    println!("cargo:rerun-if-changed=asn1/uicPretix.asn");

    Compiler::<RasnBackend, _>::new()
        .add_asn_by_path(PathBuf::from("asn1/uicRailTicketData_v1.3.5.asn"))
        .set_output_path(PathBuf::from("./asn1_gen/rail_ticket_data_v1_3_5.rs"))
        .compile().unwrap();
    Compiler::<RasnBackend, _>::new()
        .add_asn_by_path(PathBuf::from("asn1/uicRailTicketData_v2.0.3.asn"))
        .set_output_path(PathBuf::from("./asn1_gen/rail_ticket_data_v2_0_3.rs"))
        .compile().unwrap();
    Compiler::<RasnBackend, _>::new()
        .add_asn_by_path(PathBuf::from("asn1/uicRailTicketData_v3.0.5.asn"))
        .set_output_path(PathBuf::from("./asn1_gen/rail_ticket_data_v3_0_5.rs"))
        .compile().unwrap();
    Compiler::<RasnBackend, _>::new()
        .add_asn_by_path(PathBuf::from("asn1/uicBarcodeHeader_v1.0.0.asn"))
        .set_output_path(PathBuf::from("./asn1_gen/barcode_header_v1_0_0.rs"))
        .compile().unwrap();
    Compiler::<RasnBackend, _>::new()
        .add_asn_by_path(PathBuf::from("asn1/uicBarcodeHeader_v2.0.1.asn"))
        .set_output_path(PathBuf::from("./asn1_gen/barcode_header_v2_0_1.rs"))
        .compile().unwrap();
    Compiler::<RasnBackend, _>::new()
        .add_asn_by_path(PathBuf::from("asn1/uicDynamicContentData_v1.0.5.asn"))
        .set_output_path(PathBuf::from("./asn1_gen/dynamic_content_data_v1_0_5.rs"))
        .compile().unwrap();
    Compiler::<RasnBackend, _>::new()
        .add_asn_by_path(PathBuf::from("asn1/fr_intercode_v1.asn"))
        .set_output_path(PathBuf::from("./asn1_gen/fr_intercode_v1.rs"))
        .compile().unwrap();
    Compiler::<RasnBackend, _>::new()
        .add_asn_by_path(PathBuf::from("asn1/sncf_transport_v1.asn"))
        .set_output_path(PathBuf::from("./asn1_gen/sncf_transport_v1.rs"))
        .compile().unwrap();
    Compiler::<RasnBackend, _>::new()
        .add_asn_by_path(PathBuf::from("asn1/uicPretix.asn"))
        .set_output_path(PathBuf::from("./asn1_gen/uicPretix_v1.rs"))
        .compile().unwrap();
}