use std::{mem};
use anyhow::{bail};
use sha2::{Sha512, Digest};
use base64ct::{Base64, Encoding};
use pbkdf2::pbkdf2_hmac;
use rand_chacha::ChaCha20Rng;
use rsa::{RsaPrivateKey, RsaPublicKey};
use rand::SeedableRng;
use crate::manager::Manager;
use crate::password_entry::PasswordEntry;

pub trait CryptoManager {
    fn verify_master_credentials(&mut self, username: impl Into<String>, password: impl Into<String>) -> crate::Result<()>;
    fn retrieve_entries(&self) -> crate::Result<Vec<PasswordEntry>>;
    fn submit_entries(&mut self, entries: Vec<PasswordEntry>) -> crate::Result<()>;
    fn encrypt_password(&self, password_entry: PasswordEntry) -> crate::Result<String>;
}

impl CryptoManager for Manager {
    fn verify_master_credentials(&mut self, username: impl Into<String>, password: impl Into<String>) -> crate::Result<()> {
        let username = username.into();
        let password = password.into();
        let credentials = format!("{username}:{password}");
        let hasher = Sha512::new();
        let salt = rand::random::<i32>().to_string();

        let hash = hasher
            .chain_update(credentials)
            .chain_update(salt.to_string())
            .finalize();
        let rounds = 210_000;
        let encoded_hash = Base64::encode_string(&hash);
        let mut hmac_buffer = [0u8; 32];
        pbkdf2_hmac::<Sha512>(password.as_bytes(),
                              salt.as_bytes(),
                              rounds,
                              &mut hmac_buffer);
        let mut seeded_rng = ChaCha20Rng::from_seed(hmac_buffer);
        let private_key = RsaPrivateKey::new(&mut seeded_rng, 2048)?;
        let public_key = RsaPublicKey::from(&private_key);

        self.rsa_private = Some(private_key.clone());
        self.rsa_public = Some(public_key.clone());

        if let Some(profile) = &self.profile {
            let verification_hash = self.decrypt_hash(
                &profile.login_verification_hash
            )?;

            if verification_hash != encoded_hash {
                bail!("Invalid login credentials")
            } else {
                return Ok(());
            }
        }

        Ok(())
    }

    fn retrieve_entries(&self) -> crate::Result<Vec<PasswordEntry>> {
        if let Some(profile) = &self.profile {
            let entries: Vec<_> = profile.entries
                                         .clone()
                                         .iter()
                                         .filter_map(|entry| self.decrypt_hash(entry).ok())
                                         .map(|entry| entry.into())
                                         .collect();

            return Ok(entries);
        }
        Ok(vec![])
    }

    fn submit_entries(&mut self, entries: Vec<PasswordEntry>) -> crate::Result<()> {
        let profile = mem::replace(&mut self.profile, None);
        if let Some(mut profile) = profile {
            let mut encrypted_entries = entries
                .iter()
                .cloned()
                .map(|entry| entry.serialize())
                .filter_map(|entry| self.encrypt_hash(&entry).ok())
                .chain(profile.entries)
                .collect::<Vec<_>>();

            encrypted_entries.sort();
            encrypted_entries.dedup();

            profile.entries = encrypted_entries;
            let _ = mem::replace(&mut self.profile, Some(profile));
        } else {
            bail!("Can't submit to an empty profile");
        }

        Ok(())
    }

    fn encrypt_password(&self, password_entry: PasswordEntry) -> crate::Result<String> {
        self.encrypt_hash(&password_entry.serialize())
    }
}
