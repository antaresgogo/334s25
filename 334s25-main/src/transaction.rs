use serde::{Serialize,Deserialize};
use ring::signature::{Ed25519KeyPair, Signature, KeyPair, VerificationAlgorithm, EdDSAParameters};
use crate::crypto::hash::{Hashable, H256};
use rand::Rng;


pub struct SignedTransaction {
    pub transaction: RawTransaction,
    pub signature: Signature,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct RawTransaction {
    pub nonce: u64,
}

/// Create digital signature of a transaction
pub fn sign(t: &RawTransaction, key: &Ed25519KeyPair) -> Signature {
    let bytes = bincode::serialize(t).expect("Failed to serialize transaction");
    key.sign(&bytes)
}

/// Verify digital signature of a transaction, using public key instead of secret key
pub fn verify(t: &RawTransaction, public_key: &<Ed25519KeyPair as KeyPair>::PublicKey, signature: &Signature) -> bool {
    let bytes = bincode::serialize(t).expect("Failed to serialize transaction");

    let algorithm = &ring::signature::ED25519;
    ring::signature::UnparsedPublicKey::new(algorithm, public_key)
        .verify(&bytes, signature.as_ref())
        .is_ok()
}

impl Hashable for RawTransaction {
    fn hash(&self) -> H256 {
        let bytes = bincode::serialize(&self).unwrap();
        ring::digest::digest(&ring::digest::SHA256, &bytes).into()
    }
}

#[cfg(any(test, test_utilities))]
mod tests {
    use super::*;
    use crate::crypto::key_pair;

    pub fn generate_random_transaction() -> RawTransaction {
        RawTransaction {
            nonce: rand::thread_rng().gen(), 
        }
    }

    #[test]
    fn sign_verify() {
        let t = generate_random_transaction();
        let key = key_pair::random();
        let signature = sign(&t, &key);
        assert!(verify(&t, &(key.public_key()), &signature));
    }
}

