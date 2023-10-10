use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::fs::OpenOptions;

fn main() -> std::io::Result<()> {

    let p = env::var("PROFILE");
    match p
    {
        Err(e) => {Err(std::io::Error::new(std::io::ErrorKind::NotFound, e))}
        Ok(pf) =>
        {
            let mut profile = OpenOptions::new().write(true).append(true).create(true).open(&pf)?;
            profile.write_all(b"\nThis is an appended line")?;
            profile = File::open(&pf)?;
            let mut contents = String::new();
            profile.read_to_string(&mut contents)?;
            println!("File reads:\n{contents}");
            return Ok(());
        }
    }
}
