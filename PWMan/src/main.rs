use std::env;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::stdin;
use openssl::sha::sha256;
// TODO: Create sha256 for use in this program, since openSSL bugs out
use rsa;
use anyhow::bail;

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

    // let shash = s.clone();
    // let hs = sha256(&shash.into_bytes());
    // let hs = String::from_utf8(hs.to_vec())?;
    

    // println!("{s}");
    // println!("{}", hs);
    // println!("{es}");
    // add_line(s)
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