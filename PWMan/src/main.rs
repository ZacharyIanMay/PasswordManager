use std::env;

fn main() {


    println!("OpenSSL works now");
    let dir = env::var("OPENSSL_DIR");
    if dir.is_ok()
    {
        println!("{}", dir.unwrap());
    } else
    {
        println!("error");
    }
}
