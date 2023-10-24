use std::env;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::stdin;
use anyhow::bail;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use base64ct::{Base64, Encoding};
use rsa::{pkcs8::{DecodePublicKey, EncodePublicKey, DecodePrivateKey, EncodePrivateKey, LineEnding}, RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use sha2::{Sha512, Digest};
use pbkdf2::{pbkdf2_hmac, pbkdf2_hmac_array};
use hex::*;

/**
 * TODO:
 * Don't make profile based on env, allow user input
 * Clear Profile.pf
 * Place hash of text on the first line of file(include all but the hash itself)
 * Place salt on second line of file(nonencrypted)
 * Place salted hash of {username}:{password} on third line of file(encrypted)
 * Make steps of process into functions and set up flow controls
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
    // Get information from the file
    let mut username = String::new();
    let mut pass = String::new();
    let mut s = String::new();

    let original_content = read_file()?;
    let split_file = original_content.as_str().split('\n');
    let mut i = 0;
    let mut entries : Vec<&str> = Vec::new();
    let mut original_hash = "";
    let mut salt = rand::random::<i32>();
    let mut login_hash = "";
    for entry in split_file
    {
        match i
        {
            0 => {
                original_hash = entry;
            }
            1 => {
                salt = entry.parse::<i32>()?;
            }
            2 => {
                login_hash = entry;
            }
            _ => {
                entries.push(entry);
            }
        }
        i += 1;
    }

    // This verifies the file hash and rejects the input file if it does not match
    // clone entries, and combine back into one large string
    // create hash of all entries
    // check if the hash matches the stored hash, if not return an error
    let ver_entries = entries.clone();
    let mut cont : String = String::new();
    for e in ver_entries
    {
        cont.push_str(e);
    }
    let mut file_hash = Sha512::new();
    file_hash.update(cont);
    let verification = Base64::encode_string(&file_hash.finalize());
    if(verification != original_hash)
    {
        bail!("File has been modified, exiting");
    }

    // Propmt user for login credentials
    // store credentials
    // hash credentials
    // generate key for use as rng seed
    // generate RSA priv and pub keys
    // decrypt stored hash of login credentials
    // check if login credentials are correct, if not reject their login attempt
    let file_contents = "the rest of the file";
    username = read_trimmed(&mut username, "Please enter your username:")?;
    read_trimmed(&mut pass, "Please enter your password:")?;
    s = format!("{username}:{pass}");
    // Generate a salted hash based on login credentials, convert to base64
    let shash = s.clone();
    let mut hasher = Sha512::new();
    hasher.update(shash);
    hasher.update(salt.to_string());
    let shash = hasher.finalize();
    let shash = Base64::encode_string(&shash);
    println!("{}", shash);
    println!("{}", salt);
    // key derivation, this will be used to verify the user. We thus need to store the salt and the result of the derivation
    let password = pass.clone();
    let pbkdf_salt = salt;
    let n = 210_000;
    let mut k1 = [0u8; 32];
    pbkdf2_hmac::<Sha512>(password.as_bytes(), pbkdf_salt.to_string().as_bytes(), n, &mut k1);
    // This creats an RSA private key
    let mut seeded_rng = ChaCha20Rng::from_seed(k1);
    let mut srng = seeded_rng.clone();
    let priv_key = RsaPrivateKey::new(&mut seeded_rng, 2048).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);
    let pem = priv_key.to_pkcs8_pem(LineEnding::default())?.to_string();
    // checking encryption and decryption TODO: make this actually check the users credentials
    let t = "test";
    let e = enc_line(t.to_string(), pub_key.clone())?;
    let ep = e.clone();
    let d = dec_line(e, priv_key)?;
    println!("{ep}");
    println!("{d}");

    // Go through entries vector and decrypt all the entries
    // Display entries to the user
    // Allow the user to make changes to the entries

    // Once the user is done with their session re-encrypt all entries
    // clone entries and combine them into one large string
    // hash and store file contents
    // clear file of previous content
    // combine hash, salt, encrypted hash, and file contents, and write to file
    let mut ver_hasher = Sha512::new();
    ver_hasher.update(""); // TODO: replace with new file contents
    let ver_hash = Base64::encode_string(&ver_hasher.finalize());
    let written = ver_hash + "\n" + salt.to_string().as_str() + "\n" + enc_line(shash, pub_key.clone())?.as_str() + "\n" + file_contents;
    add_line(written)?;
    // add_line(eh)?;
    // add_line(pem)?;
    // add_line(s)?;
    // add_line(format!("{}\n", salt.to_string()))?;
    print_file()
}

fn enc_line(s: String, pub_key : RsaPublicKey) -> anyhow::Result<String>
{
    println!("{s}");
    let mut rng = rand::thread_rng();
    let enc = pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, s.as_bytes()).expect("failed to encrypt");
    println!("{:?}", enc);
    let enc_h = hex::encode(enc);
    println!("{enc_h}");
    return Ok(enc_h);
    
}

fn dec_line(s: String, priv_key : RsaPrivateKey) -> anyhow::Result<String>
{
    let dec : Vec<u8> = hex::decode(s)?;
    println!("{:?}", dec);
    let dec_s = priv_key.decrypt(Pkcs1v15Encrypt, &dec)?;
    let ret = std::str::from_utf8(&dec_s)?;
    println!("{ret}");
    return Ok(ret.to_string());
}

fn read_trimmed(s : &mut String, query : &str) -> anyhow::Result<String>
{
    println!("{}", query);
    let std = stdin();
    std.read_line(s)?;
    let s = s.trim();
    return Ok(s.to_string());
}

fn add_line(line : String) -> anyhow::Result<()> {
    let p = env::var("PROFILE");
    match p
    {
        Err(e) => {bail!("Couldn't find ENV var")}
        Ok(pf) =>
        {
            let mut profile = OpenOptions::new().write(true).create(true).open(&pf)?;
            let s = format!("{line}");
            profile.write_all(s.as_bytes())?;
            return Ok(());
        }
    }
}

fn print_file() -> anyhow::Result<()> {
    let p = env::var("PROFILE");
    match p
    {
        Err(e) => {bail!("Couldn't find ENV var")}
        Ok(pf) =>
        {
            let mut profile = File::open(&pf)?;
            let mut contents = String::new();
            profile.read_to_string(&mut contents)?;
            println!("File reads:\n{contents}");
            return Ok(());
        }
    }
}

fn read_file() -> anyhow::Result<String> {
    let p = env::var("PROFILE");
    match p
    {
        Err(e) => {bail!("Couldn't find ENV var")}
        Ok(pf) =>
        {
            let mut profile = File::open(&pf)?;
            let mut contents = String::new();
            profile.read_to_string(&mut contents)?;
            return Ok(contents);
        }
    }
}