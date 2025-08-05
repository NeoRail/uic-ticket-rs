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

#[derive(Debug)]
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
        let pkey = PublicKey::from_pem(key)?;
        let issuer_keys = self.issuers.entry(issuer.to_string()).or_insert_with(IssuerKeys::new);
        issuer_keys.keys.insert(key_id.to_string(), pkey);
        Ok(())
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
        use signature::{Verifier, DigestVerifier};
        use der::Decode;
        use digest::Digest;

        match ticket {
            crate::Ticket::UicTlbTicket(t) => {
                let pk = self.issuers.get(t.security_provider_rics.as_ref())
                    .ok_or(VerificationError::UnknownIssuer)?
                    .keys.get(t.security_provider_key_id.as_ref())
                    .ok_or(VerificationError::UnknownKey)?;
                let dsa_pk = match pk {
                    PublicKey::DSA(pk) => pk,
                    _ => return Err(VerificationError::InvalidSignature),
                };

                let sig = dsa::Signature::try_from(Self::make_tlb_sig(&t.signature).as_slice())
                    .map_err(|_| VerificationError::InvalidSignature)?;

                if t.version == 1 {
                    let mut digest = sha1::Sha1::new();
                    digest.update(&t.records.tbs_data);
                    dsa_pk.verify_digest(digest, &sig)
                        .map_err(|_| VerificationError::InvalidSignature)?;
                } else if t.version == 2 {
                    let mut digest = sha2::Sha256::new();
                    digest.update(&t.records.tbs_data);
                    dsa_pk.verify_digest(digest, &sig)
                        .map_err(|_| VerificationError::InvalidSignature)?;
                } else {
                    return Err(VerificationError::InvalidSignature);
                }

                Ok(())
            }
            crate::Ticket::UicDosipasTicket(t) => {
                let pk = self.issuers.get(&t.security_provider)
                    .ok_or(VerificationError::UnknownIssuer)?
                    .keys.get(&(t.key_id.to_string()))
                    .ok_or(VerificationError::UnknownKey)?;

                match pk {
                    PublicKey::DSA(pk) => {
                        let sig = dsa::Signature::from_der(&t.level1_signature)
                            .map_err(|_| VerificationError::InvalidSignature)?;

                        if t.level1_signing_alg.as_ref() == Some(&DSA_WITH_SHA1) {
                            let mut digest = sha1::Sha1::new();
                            digest.update(&t.level1_signed_data);
                            pk.verify_digest(digest, &sig)
                                .map_err(|_| VerificationError::InvalidSignature)?;
                        } else if t.level1_signing_alg.as_ref() == Some(&DSA_WITH_SHA224) {
                            let mut digest = sha2::Sha224::new();
                            digest.update(&t.level1_signed_data);
                            pk.verify_digest(digest, &sig)
                                .map_err(|_| VerificationError::InvalidSignature)?;
                        } else if t.level1_signing_alg.as_ref() == Some(&DSA_WITH_SHA256) {
                            let mut digest = sha2::Sha256::new();
                            digest.update(&t.level1_signed_data);
                            pk.verify_digest(digest, &sig)
                                .map_err(|_| VerificationError::InvalidSignature)?;
                        } else {
                            return Err(VerificationError::InvalidSignature);
                        }
                    },
                    PublicKey::P256(pk) => {
                        let sig = ecdsa::Signature::from_der(&t.level1_signature)
                            .map_err(|_| VerificationError::InvalidSignature)?;

                        if t.level1_signing_alg.as_ref() == Some(&ECDSA_WITH_SHA256) {
                            pk.verify(&t.level1_signed_data, &sig)
                                .map_err(|_| VerificationError::InvalidSignature)?;
                        } else {
                            return Err(VerificationError::InvalidSignature);
                        }
                    }
                    PublicKey::Ed25519(pk) => {
                        let sig = ed25519_dalek::Signature::from_slice(&t.level1_signature)
                            .map_err(|_| VerificationError::InvalidSignature)?;

                        if t.level1_signing_alg.as_ref() == Some(&ED25519) {
                            pk.verify(&t.level1_signed_data, &sig)
                                .map_err(|_| VerificationError::InvalidSignature)?;
                        } else {
                            return Err(VerificationError::InvalidSignature);
                        }
                    }
                }

                if let Some(l2_sig) = &t.level2_signature {
                    let l2_pk = t.level2_public_key
                        .as_ref()
                        .ok_or(VerificationError::InvalidSignature)?;

                    match l2_pk {
                        PublicKey::P256(l2_pk) => {
                            let sig = ecdsa::Signature::from_der(l2_sig)
                                .map_err(|_| VerificationError::InvalidSignature)?;

                            if t.level2_signing_alg.as_ref() == Some(&ECDSA_WITH_SHA256) {
                                l2_pk.verify(&t.level2_signed_data, &sig)
                                    .map_err(|_| VerificationError::InvalidSignature)?;
                            } else {
                                return Err(VerificationError::InvalidSignature);
                            }
                        },
                        _ => return Err(VerificationError::InvalidSignature),
                    }
                } else if t.level2_public_key.is_some() {
                    return Err(VerificationError::InvalidSignature);
                }

                Ok(())
            }
        }
    }
}

#[derive(Debug)]
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

#[derive(Debug, Clone)]
#[non_exhaustive]
pub(crate) enum PublicKey {
    DSA(dsa::VerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl PublicKey {
    const DSA_OID: spki::ObjectIdentifier = spki::ObjectIdentifier::new_unwrap("1.2.840.10040.4.1");
    const EC_OID: spki::ObjectIdentifier = spki::ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    const ED25519_OID: spki::ObjectIdentifier = spki::ObjectIdentifier::new_unwrap("1.3.101.112");
    const SECP256_R1_OID: spki::ObjectIdentifier = spki::ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

    fn from_pem(data: &str) -> Result<Self, crate::Error> {
        let p = pem::parse(data.as_bytes())
            .map_err(|e| crate::Error::CryptographyError(Box::new(e)))?;
        if p.tag() != "PUBLIC KEY" {
            return Err(crate::Error::UnsupportedData(format!("unexpected PEM tag: {}", p.tag())));
        }

        let spki_ref = spki::SubjectPublicKeyInfo::try_from(p.contents())
            .map_err(|e| crate::Error::CryptographyError(Box::new(e)))?;

        match spki_ref.algorithm.oid {
            Self::DSA_OID => {
                Ok(Self::DSA(dsa::VerifyingKey::try_from(spki_ref)
                    .map_err(|e| crate::Error::CryptographyError(Box::new(e)))?))
            },
            Self::EC_OID => {
                let curve = spki_ref.algorithm.parameters_oid()
                    .map_err(|e| crate::Error::CryptographyError(Box::new(e)))?;
                match curve {
                    Self::SECP256_R1_OID => {
                        Ok(Self::P256(p256::ecdsa::VerifyingKey::try_from(spki_ref)
                            .map_err(|e| crate::Error::CryptographyError(Box::new(e)))?))
                    }
                    o => Err(crate::Error::UnsupportedData(format!("unsupported EC curve {o}")))
                }
            }
            Self::ED25519_OID => {
                Ok(Self::Ed25519(ed25519_dalek::VerifyingKey::try_from(spki_ref)
                    .map_err(|e| crate::Error::CryptographyError(Box::new(e)))?))
            }
            o => Err(crate::Error::UnsupportedData(format!("unsupported public key type {o}")))
        }
    }
}