use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Lines, Write};
use std::path::PathBuf;
use std::{str};
use anyhow::{anyhow, bail};
use base64ct::{Base64, Encoding};
use log::error;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use sha2::{Sha512, Digest};
use crate::crypto_manager::CryptoManager;
use crate::password_entry::PasswordEntry;

#[derive(Debug, Default)]
pub struct Manager {
    pub profile: Profile,
    pub rsa_public: Option<RsaPublicKey>,
    pub rsa_private: Option<RsaPrivateKey>,
}

#[derive(Debug)]
pub struct Profile {
    pub original_hash: String,
    pub salt: i32,
    pub login_verification_hash: String,
    pub entries: Vec<String>,
    pub new_file: bool,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            original_hash: "".to_string(),
            salt: rand::random::<i32>(),
            login_verification_hash: "".to_string(),
            entries: vec![],
            new_file: true,
        }
    }
}

impl Profile {
    fn read_lines(mut lines: Lines<BufReader<File>>) -> Option<Self> {
        let original_hash = lines.next()?.ok()?;
        let salt: i32 = {
            let salt_string = lines.next()?.ok()?;
            salt_string.parse().ok()?
        };
        let login_verification_hash = lines.next()?.ok()?;
        let entries: Vec<_> = lines.filter_map(|line| line.ok()).collect();
        Some(Self {
            original_hash,
            login_verification_hash,
            salt,
            entries,
            new_file: false,
        })
    }

    fn from_file(path: &PathBuf) -> crate::Result<Self> {
        let file = File::open(path)?;
        let buf_reader = BufReader::new(file);
        if buf_reader.capacity() == 0 {
            bail!("Empty file");
        }
        let profile = Self::read_lines(buf_reader.lines());
        if let Some(profile) = profile {
            return Self::verify_profile(profile);
        } else {
            bail!("Couldn't read the file")
        }
    }

    fn verify_profile(profile: Self) -> crate::Result<Self> {
        let mut file_string = String::new();
        for entry in &profile.entries {
            file_string.push_str(entry);
        }
        file_string.push_str(&profile.login_verification_hash);
        let mut file_hasher = Sha512::new();
        file_hasher.update(file_string);
        let validation_hash = Base64::encode_string(&file_hasher.finalize());
        if validation_hash != profile.original_hash {
            // TODO: Change this panic into a custom error to correctly bail later
            panic!("File has been modified, exiting");
        }

        Ok(profile)
    }

    pub fn save_file(&self, path: PathBuf) -> crate::Result<()> {
        let previous_entries = self
            .entries
            .iter()
            .cloned()
            .reduce(|accumulator, value| accumulator + "\n" + &value);

        let entries_string = previous_entries
            .clone()
            .unwrap_or(String::new())
            .replace("\n", "");

        let content = entries_string + &self.login_verification_hash;

        let hash = Sha512::new()
            .chain_update(content)
            .finalize();
        let hashed_content = Base64::encode_string(&hash);
        let file_content = match previous_entries {
            Some(previous_entries) => {
                hashed_content + "\n"
                    + &self.salt.to_string() + "\n"
                    + &self.login_verification_hash + "\n"
                    + &previous_entries
            }
            None => {
                hashed_content + "\n"
                    + &self.salt.to_string() + "\n"
                    + &self.login_verification_hash
            }
        };

        let mut profile = OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(path)?;

        profile.write_all(file_content.as_bytes())?;

        Ok(())
    }
}

impl Manager {
    pub fn new(file_path: &PathBuf) -> Self {
        let result = Profile::from_file(file_path);
        return match result {
            Ok(profile) => {
                Self {
                    profile,
                    ..Default::default()
                }
            }
            Err(e) => {
                error!("{e}");
                Self::default()
            }
        };
    }

    pub fn add_password(&mut self, username: String, password: String, site: String) -> crate::Result<()> {
        let entry: PasswordEntry = (site, username, password).into();
        let serialized = entry.serialize();
        let encrypted = self.encrypt_hash(&serialized)?;
        self.profile.entries.push(encrypted);

        Ok(())
    }

    pub fn delete_password(&mut self, site: String) -> crate::Result<()> {
        let mut entries = self.retrieve_entries()?;
        let position = entries
            .iter()
            .position(|entry| entry.site == site)
            .ok_or(anyhow!("Failed to find the entry"))?;

        entries.remove(position);

        self.submit_entries(entries)
    }

    pub fn get_password(&self, site: String) -> crate::Result<PasswordEntry> {
        let entries = self.retrieve_entries()?;

        let entry = entries
            .iter()
            .find(|entry| entry.site == site)
            .ok_or(anyhow!("Failed to find the entry"))?
            .clone();

        Ok(entry)
    }

    pub fn update_password(&mut self, site: String, username: String, password: String) -> crate::Result<()> {
        let mut entries = self.retrieve_entries()?;
        let position = entries
            .iter()
            .position(|entry| entry.site == site)
            .ok_or(anyhow!("Failed to find the entry"))?;

        entries[position] = (site, username, password).into();

        self.submit_entries(entries)
    }

    pub(crate) fn decrypt_hash(&self, hash: &String) -> crate::Result<String> {
        let private_key = self.rsa_private.clone().ok_or(anyhow!("Failed to retrieve private key"))?;
        let decoded_hash = hex::decode(hash)?;
        let decrypted_hash = private_key.decrypt(Pkcs1v15Encrypt, &decoded_hash)?;
        let decrypted_str = str::from_utf8(&decrypted_hash)?;
        Ok(decrypted_str.to_string())
    }

    pub(crate) fn encrypt_hash(&self, hash: &String) -> crate::Result<String> {
        let public_key = &self.rsa_public.clone().ok_or(anyhow!("Failed to retrieve public key"))?;
        let mut rng = rand::thread_rng();
        let encrypted_hash = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, hash.as_bytes())?;
        let encoded_hash = hex::encode(encrypted_hash);
        Ok(encoded_hash)
    }
}
