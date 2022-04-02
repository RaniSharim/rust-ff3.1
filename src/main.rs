pub mod ff31;

fn main() {
    // abcdefghijklmnopqrstuvwxyz
    let x = ff31::FF31::new(&[0u8; 16], "0123456789");
    let tweak = [0; 7];

    let enc = x.encrypt("001001", &tweak);
    let dec = x.decrypt(&enc, &tweak);

    println!("{:?}", &dec);
}
