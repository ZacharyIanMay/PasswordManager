use std::env;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::stdin;
use anyhow::bail;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use base64ct::{Base64, Encoding};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use sha2::{Sha512, Digest};
use pbkdf2::{pbkdf2_hmac, pbkdf2_hmac_array};

/**
 * TODO:
 * Don't make profile based on env, allow user input
 * Clear Profile.pf
 * Place hash of text on the first line of file(include all but the hash itself)
 * Place salt on second line of file(nonencrypted)
 * Place password encrypted secret key on third line of file
 * Place salted hash on fourth line of file(encrypted)
 * 
 * 
 * Login Process:
 * check that line 1(hash of contents) is valid
 * take user input
 * format input
 * add salt
 * hash
 * use to decrypt third line(secret key)
 * check if the hash properly decrypted the secret key via fourth line(stored version of salted hash)
 * 
 * 
 * After any additions or edits to the file, rehash the file and store the hash on the first line
 */

fn main() -> anyhow::Result<()>
{
    let mut username = String::new();
    let mut pass = String::new();
    let mut s = String::new();
    println!("Please enter your username:");
    username = read_trimmed(&mut username)?.to_string();
    if(username == "test")
    {
        println!("Please enter you password:");
        read_trimmed(&mut pass)?.to_string();
        s = format!("{username}:{pass}");
    }
    else
    {
        println!("\n\n'{}'", &username);
        s = "Username isn't 'test'\n".to_string();
    }

    // Generate a salted hash based on login credentials, convert to base64
    let shash = s.clone();
    let mut hasher = Sha512::new();
    hasher.update(shash);
    let salt = rand::random::<i32>();
    hasher.update(salt.to_string());
    let shash = hasher.finalize();
    let shash = Base64::encode_string(&shash);
    println!("{}", shash);
    println!("{}", salt);

    // key derivation
    let password = pass.clone();
    let pbkdf_salt = salt;
    let n = 210_000;
    let mut k1 = [0u8; 32];
    pbkdf2_hmac::<Sha512>(password.as_bytes(), pbkdf_salt.to_string().as_bytes(), n, &mut k1);
    println!("{:?}", k1);

    let mut seeded_rng = ChaCha20Rng::from_seed(k1);
    let priv_key = RsaPrivateKey::new(&mut seeded_rng, 2048).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);

    // Look for a Password based key derivation function, likely PBKDF2 from rustcrypto
    add_line(s)?;
    add_line(format!("{}\n", salt.to_string()))
}

fn read_trimmed(s : &mut String) -> anyhow::Result<&str>
{
    let std = stdin();
    std.read_line(s)?;
    let s = s.trim();
    return Ok(s);
}

fn add_line(line : String) -> anyhow::Result<()> {
    let p = env::var("PROFILE");
    match p
    {
        Err(e) => {bail!("Couldn't find ENV var")}
        Ok(pf) =>
        {
            let mut profile = OpenOptions::new().write(true).append(true).create(true).open(&pf)?;
            let s = format!("{line}");
            profile.write_all(s.as_bytes())?;
            profile = File::open(&pf)?;
            let mut contents = String::new();
            profile.read_to_string(&mut contents)?;
            println!("File reads:\n{contents}");
            return Ok(());
        }
    }
}