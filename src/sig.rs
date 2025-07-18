const DSA_WITH_SHA1: rasn::types::ObjectIdentifier = rasn::types::ObjectIdentifier::new_unchecked(
    std::borrow::Cow::Borrowed(&[1, 2, 840, 10040, 4, 3]));
const DSA_WITH_SHA224: rasn::types::ObjectIdentifier = rasn::types::ObjectIdentifier::new_unchecked(
    std::borrow::Cow::Borrowed(&[2, 16, 840, 1, 101, 3, 4, 3, 1]));
const DSA_WITH_SHA256: rasn::types::ObjectIdentifier = rasn::types::ObjectIdentifier::new_unchecked(
    std::borrow::Cow::Borrowed(&[2, 16, 840, 1, 101, 3, 4, 3, 2]));
const ECDSA_WITH_SHA256: rasn::types::ObjectIdentifier = rasn::types::ObjectIdentifier::new_unchecked(
    std::borrow::Cow::Borrowed(&[1, 2, 840, 10045, 4, 3, 2]));
const ED25519: rasn::types::ObjectIdentifier = rasn::types::ObjectIdentifier::new_unchecked(
    std::borrow::Cow::Borrowed(&[1, 3, 101, 112]));

pub struct PublicKeyDB {
    issuers: std::collections::HashMap<String, IssuerKeys>
}

#[derive(Debug, Copy, Clone)]
pub enum VerificationError {
    UnsupportedTicketType,
    UnknownIssuer,
    UnknownKey,
    InvalidSignature,
}

#[derive(rasn::AsnType, Debug, Clone, rasn::Encode, PartialEq, Eq, Hash)]
struct DERSig {
    r: rasn::types::Integer,
    s: rasn::types::Integer,
}

impl PublicKeyDB {
    pub fn new() -> Self {
        Self {
            issuers: std::collections::HashMap::new()
        }
    }

    pub fn load_key_pem(&mut self, issuer: &str, key_id: &str, key: &str) -> Result<(), crate::Error> {
        let pkey = botan::Pubkey::load_pem(key)?;
        let issuer_keys = self.issuers.entry(issuer.to_string()).or_insert_with(IssuerKeys::new);
        issuer_keys.keys.insert(key_id.to_string(), PublicKey {
            pkey
        });
        Ok(())
    }

    pub fn get_public_key(&self, issuer: &str, key_id: &str) -> Option<&PublicKey> {
        self.issuers.get(issuer)?.keys.get(key_id)
    }

    fn make_tlb_sig(signature: &crate::tlb::TicketSignature) -> Vec<u8> {
        match signature {
            crate::tlb::TicketSignature::ASN1Signature(s) => {
                let mut o = 0;
                while s[o] == 0 {
                    o += 1
                }
                s[o..].to_owned()
            }
            crate::tlb::TicketSignature::RawSignature(s) => {
                let (r, s) = (&s[0..32], &s[32..64]);
                let mut or = 0;
                let mut os = 0;
                while r[or] == 0 {
                    or += 1
                }
                while s[os] == 0 {
                    os += 1
                }
                let r = &r[or..];
                let s = &s[os..];
                let r = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, r);
                let s = num_bigint::BigInt::from_bytes_be(num_bigint::Sign::Plus, s);
                let sig = DERSig {
                    r: rasn::types::Integer::from(r),
                    s: rasn::types::Integer::from(s)
                };
                rasn::der::encode(&sig).unwrap()
            }
        }
    }

    pub fn verify_ticket(&self, ticket: &crate::Ticket) -> Result<(), VerificationError> {
        match ticket {
            crate::Ticket::UicTlbTicket(t) => {
                let pk = self.issuers.get(t.security_provider_rics.as_ref())
                    .ok_or(VerificationError::UnknownIssuer)?
                    .keys.get(t.security_provider_key_id.as_ref())
                    .ok_or(VerificationError::UnknownKey)?;

                let mut verifier = pk.verifier(if t.version == 1 {
                    "SHA-1"
                } else if t.version == 2 {
                    "SHA-256"
                } else {
                    unreachable!()
                });
                verifier.update(&t.records.tbs_data).unwrap();

                let sig = Self::make_tlb_sig(&t.signature);
                match verifier.finish(&sig) {
                    Ok(true) => Ok(()),
                    _ => Err(VerificationError::InvalidSignature)
                }
            }
            crate::Ticket::UicDosipasTicket(t) => {
                let pk = self.issuers.get(&t.security_provider)
                    .ok_or(VerificationError::UnknownIssuer)?
                    .keys.get(&(t.key_id.to_string()))
                    .ok_or(VerificationError::UnknownKey)?;

                let pk_algo = pk.pkey.algo_name()
                    .map_err(|_| VerificationError::InvalidSignature)?;
                let mut verifier = if pk_algo == "DSA" && t.level1_signing_alg.as_ref() == Some(&DSA_WITH_SHA1) {
                    pk.verifier("SHA-1")
                } else if pk_algo == "DSA" && t.level1_signing_alg.as_ref() == Some(&DSA_WITH_SHA224) {
                    pk.verifier("SHA-224")
                } else if pk_algo == "DSA" && t.level1_signing_alg.as_ref() == Some(&DSA_WITH_SHA256) {
                    pk.verifier("SHA-256")
                } else if pk_algo == "EC" && t.level1_signing_alg.as_ref() == Some(&ECDSA_WITH_SHA256) {
                    pk.verifier("SHA-256")
                } else if pk_algo == "Ed25519" && t.level1_signing_alg.as_ref() == Some(&ED25519) {
                    pk.verifier("Pure")
                } else {
                    return Err(VerificationError::InvalidSignature);
                };

                verifier.update(&t.level1_signed_data).unwrap();
                match verifier.finish(&t.level1_signature) {
                    Ok(true) => Ok(()),
                    _ => Err(VerificationError::InvalidSignature)
                }
            },
            _ => Err(VerificationError::UnsupportedTicketType)
        }
    }
}

pub struct IssuerKeys {
    keys: std::collections::HashMap<String, PublicKey>
}

impl IssuerKeys {
    fn new() -> Self {
        Self {
            keys: std::collections::HashMap::new()
        }
    }
}

pub struct PublicKey {
    pkey: botan::Pubkey,
}

impl PublicKey {
    fn verifier(&self, alg: &str) -> botan::Verifier {
        botan::Verifier::new_with_der_formatted_signatures(&self.pkey, alg).unwrap()
    }
}