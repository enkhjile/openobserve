use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use openidconnect::{Nonce, PkceCodeVerifier};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::Error;

const TRANSACTION_TTL: Duration = Duration::from_secs(300);
const MAX_TRANSACTIONS: usize = 4096;

#[derive(Default)]
pub(crate) struct Transactions(Mutex<HashMap<[u8; 32], Transaction>>);

impl Transactions {
    pub(crate) fn insert(
        &self,
        state: &str,
        binding: &str,
        nonce: Nonce,
        pkce: PkceCodeVerifier,
        now: Instant,
    ) -> Result<(), Error> {
        if binding.len() < 32 || binding.len() > 256 {
            return Err(Error::TransactionRejected);
        }
        let mut pending = self.0.lock().map_err(|_| Error::TransactionRejected)?;
        pending.retain(|_, transaction| now.duration_since(transaction.created) < TRANSACTION_TTL);
        if pending.len() >= MAX_TRANSACTIONS {
            return Err(Error::Capacity);
        }
        pending.insert(
            digest(state),
            Transaction {
                binding: digest(binding),
                nonce,
                pkce,
                created: now,
            },
        );
        Ok(())
    }

    pub(crate) fn take(
        &self,
        state: &str,
        binding: &str,
        now: Instant,
    ) -> Result<Transaction, Error> {
        if state.len() > 256 || binding.len() > 256 {
            return Err(Error::TransactionRejected);
        }
        let transaction = self
            .0
            .lock()
            .map_err(|_| Error::TransactionRejected)?
            .remove(&digest(state))
            .ok_or(Error::TransactionRejected)?;
        if now.duration_since(transaction.created) >= TRANSACTION_TTL
            || !bool::from(transaction.binding.ct_eq(&digest(binding)))
        {
            return Err(Error::TransactionRejected);
        }
        Ok(transaction)
    }
}

pub(crate) struct Transaction {
    binding: [u8; 32],
    pub(crate) nonce: Nonce,
    pub(crate) pkce: PkceCodeVerifier,
    created: Instant,
}

fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insert(transactions: &Transactions, state: &str, now: Instant) {
        transactions
            .insert(
                state,
                "12345678901234567890123456789012",
                Nonce::new("nonce".into()),
                PkceCodeVerifier::new("verifier".into()),
                now,
            )
            .unwrap();
    }

    #[test]
    fn state_is_single_use_browser_bound_and_expires() {
        let transactions = Transactions::default();
        let now = Instant::now();
        let binding = "12345678901234567890123456789012";
        insert(&transactions, "valid", now);
        assert!(transactions.take("invalid", binding, now).is_err());
        assert!(transactions.take("valid", binding, now).is_ok());
        assert!(transactions.take("valid", binding, now).is_err());
        insert(&transactions, "wrong-browser", now);
        assert!(
            transactions
                .take("wrong-browser", "another-browser", now)
                .is_err()
        );
        assert!(transactions.take("wrong-browser", binding, now).is_err());
        insert(&transactions, "expired", now);
        assert!(
            transactions
                .take("expired", binding, now + TRANSACTION_TTL)
                .is_err()
        );
    }

    #[test]
    fn pending_transactions_are_bounded_and_expiry_reclaims_capacity() {
        let transactions = Transactions::default();
        let now = Instant::now();
        for n in 0..MAX_TRANSACTIONS {
            insert(&transactions, &n.to_string(), now);
        }
        assert!(matches!(
            transactions.insert(
                "full",
                "12345678901234567890123456789012",
                Nonce::new("n".into()),
                PkceCodeVerifier::new("v".into()),
                now
            ),
            Err(Error::Capacity)
        ));
        insert(&transactions, "reclaimed", now + TRANSACTION_TTL);
    }
}
