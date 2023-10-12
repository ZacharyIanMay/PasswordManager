use std::env;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::stdin;

fn main() -> std::io::Result<()>
{
    let mut username = String::new();
    let mut pass = String::new();
    let mut s = String::new();
    let inp = stdin();
    println!("Please enter your username:");
    inp.read_line(&mut username)?;
    if(&username == "test")
    {
        println!("Please enter you password:");
        inp.read_line(&mut pass)?;
        s = format!("{username}:{pass}");
    }
    else
    {
        println!("\n\n'{}'", &username);
        s = "Username isn't 'test'\n".to_string();
    }
    
    add_line(s)
}

fn add_line(line : String) -> std::io::Result<()> {
    let p = env::var("PROFILE");
    match p
    {
        Err(e) => {Err(std::io::Error::new(std::io::ErrorKind::NotFound, e))}
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