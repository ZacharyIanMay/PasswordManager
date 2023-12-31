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

    let original_content = read_file()?;
    
    let split_file = original_content.as_str().split('\n');
    let mut entries : Vec<String> = Vec::new();
    let mut original_hash = "";
    let mut salt = rand::random::<i32>();
    let mut login_hash = "";

    let mut new_file = 0;
    
    if original_content.is_empty()
    {
        new_file = 1;
    }
    else
    {
        let mut i = 0;
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
                    entries.push(entry.to_string());
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
            cont.push_str(e.as_str());
        }
        cont.push_str(login_hash);
        let mut file_hash = Sha512::new();
        file_hash.update(cont);
        let verification = Base64::encode_string(&file_hash.finalize());
        if verification != original_hash
        {
            bail!("File has been modified, exiting");
        }
    }
    

    // Propmt user for login credentials
    // store credentials
    // hash credentials
    // generate key for use as rng seed
    // generate RSA priv and pub keys
    // decrypt stored hash of login credentials
    // check if login credentials are correct, if not reject their login attempt
    username = read_trimmed(&mut username, "Please enter your username:")?;
    read_trimmed(&mut pass, "Please enter your password:")?;
    let s = format!("{username}:{pass}");
    println!("\nVerifying . . .\n");
    // Generate a salted hash based on login credentials, convert to base64
    let shash = s.clone();
    let mut hasher = Sha512::new();
    hasher.update(shash);
    hasher.update(salt.to_string());
    let shash = hasher.finalize();
    let shash = Base64::encode_string(&shash);
    // key derivation, this will be used to verify the user. We thus need to store the salt and the result of the derivation
    let password = pass.clone();
    let pbkdf_salt = salt;
    let n = 210_000;
    let mut k1 = [0u8; 32];
    pbkdf2_hmac::<Sha512>(password.as_bytes(), pbkdf_salt.to_string().as_bytes(), n, &mut k1);
    // This creats an RSA private key
    let mut seeded_rng = ChaCha20Rng::from_seed(k1);
    let priv_key = RsaPrivateKey::new(&mut seeded_rng, 2048).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);
    //let pem = priv_key.to_pkcs8_pem(LineEnding::default())?.to_string();

    if new_file == 0
    {
        // checking encryption and decryption
        let valid = dec_line(login_hash.to_string(), priv_key.clone())?;
        if valid != shash
        {
            bail!("Invalid login credentials");
        }
        println!("Your current managed sites are:");
        for entry in entries.clone()
        {
            println!("{}", dec_line(entry.to_string(), priv_key.clone())?);
        }
    }

    let mut escaped = false;
    while !escaped
    {
        let options = "Please enter the number corresponding to the option you would like to select\n 1. Add a new password\n 2. Edit a password\n 3. Remove a password\n Other: Exit";
        let mut option = String::new();
        option = read_trimmed(&mut option, options)?;
        match option.as_str()
        {
            "1" => {
                let mut site = String::new();
                let mut user = String::new();
                let mut pass = String::new();
                site = read_trimmed(&mut site, "Please type new entries site:")?;
                user = read_trimmed(&mut user, "Please type new entries username:")?;
                pass = read_trimmed(&mut pass, "Please type new entries password:")?;
                entries.push(add_password(pub_key.clone(), site, user, pass)?);
            }
            "2" => {
                let mut site = String::new();
                let mut user = String::new();
                let mut pass = String::new();
                site = read_trimmed(&mut site, "Please type the site's name:")?;
                user = read_trimmed(&mut user, "Please type the site's username:")?;
                pass = read_trimmed(&mut pass, "Please type the new password:")?;
                delete_password(priv_key.clone(), &mut entries, site.clone())?;
                entries.push(add_password(pub_key.clone(), site, user, pass)?);
            }
            "3" => {
                let mut site = String::new();
                site = read_trimmed(&mut site, "Please enter the name of the site to remove from management:")?;
                delete_password(priv_key.clone(), &mut entries, site)?;
            }
            _ => {
                escaped = true;
                // Do nothing, exit
            }
        }

        println!("");
        println!("Your current managed sites are:");
        for entry in entries.clone()
        {
            println!("{}", dec_line(entry.to_string(), priv_key.clone())?);
        }
    }
    
    // Go through entries vector and decrypt all the entries
    // Display entries to the user
    // Allow the user to make changes to the entries

    // Once the user is done with their session re-encrypt all entries
    // clone entries and combine them into one large string
    // hash and store file contents
    // clear file of previous content
    // combine hash, salt, encrypted hash, and file contents, and write to file
    let mut file_contents = String::new();
    let mut c = 0;
    for entry in entries.clone()
    {
        if c == 0
        {
            file_contents = entry;
        }
        else
        {
            file_contents = file_contents + "\n" + entry.as_str();
        }
        c += 1;
    }

    let enc_log = enc_line(shash, pub_key.clone())?;
    let mut ver_cont : String = String::new();
    for e in entries.clone()
    {
        ver_cont.push_str(e.as_str());
    }
    ver_cont.push_str(enc_log.clone().as_str());
    let mut ver_hasher = Sha512::new();
    ver_hasher.update(ver_cont);
    let ver_hash = Base64::encode_string(&ver_hasher.finalize());

    // Prevents writing a blank line at the end of the file, which causes errors on attempting to decrypt entries
    let prewrite = ver_hash + "\n" + salt.to_string().as_str() + "\n" + enc_log.as_str();
    let written =  prewrite.clone() + "\n" + file_contents.as_str();
    if !file_contents.is_empty()
    {
        add_line(written)?;
    }
    else
    {
        add_line(prewrite)?;
    }
    print_file()
}

fn add_password<'a>(pub_key : RsaPublicKey, site : String, user : String, pass : String) -> anyhow::Result<String>
{
    let s = format!("{site}:{user}:{pass}");
    let e = enc_line(s, pub_key)?;
    return Ok(e);
}

fn delete_password(priv_key : RsaPrivateKey, entries : &mut Vec<String>, site : String) -> anyhow::Result<()>
{
    let mut copy : Vec<String> = vec![];
    for entry in entries.clone()
    {
        let mut e = dec_line(entry, priv_key.clone())?;
        // TODO: split the entry into just the site so that the check returns true
        let ind = e.clone();
        let ind = ind.split(":");
        let mut iter = 0;
        for part in ind
        {
            if iter == 0
            {
                e = part.to_string();
            }
            iter += 1;
        }
        copy.push(e);
    }
    let ind = copy.iter().position(|x| *x == site);
    match ind
    {
        Some(i) => {
            entries.remove(i);
            return Ok(());
        }
        _ => {
            println!("{:?}", copy);
            bail!("No such site");
        }
    }
}

fn enc_line(s: String, pub_key : RsaPublicKey) -> anyhow::Result<String>
{
    let mut rng = rand::thread_rng();
    let enc = pub_key.encrypt(&mut rng, Pkcs1v15Encrypt, s.as_bytes()).expect("failed to encrypt");
    let enc_h = hex::encode(enc);
    return Ok(enc_h);
    
}

fn dec_line(s: String, priv_key : RsaPrivateKey) -> anyhow::Result<String>
{
    let dec : Vec<u8> = hex::decode(s)?;
    let dec_s = priv_key.decrypt(Pkcs1v15Encrypt, &dec)?;
    let ret = std::str::from_utf8(&dec_s)?;
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
        Err(e) => {bail!("Couldn't find ENV var. Error: {}", e)}
        Ok(pf) =>
        {
            let mut profile = OpenOptions::new().write(true).create(true).open(&pf)?;
            profile.set_len(0)?;
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
        Err(e) => {bail!("Couldn't find ENV var. Error: {}", e)}
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
        Err(e) => {bail!("Couldn't find ENV var. Error: {}", e)}
        Ok(pf) =>
        {
            let mut profile = File::open(&pf)?;
            let mut contents = String::new();
            profile.read_to_string(&mut contents)?;
            return Ok(contents);
        }
    }
}