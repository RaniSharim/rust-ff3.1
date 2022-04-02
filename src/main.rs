pub mod ff31;

fn main() {
    let x = ff31::FF31::new(&[1, 2, 3], "abc");
    let tweak = [0; 7];

    let enc = x.encrypt("abc", &tweak);
    let dec = x.decrypt(&enc, &tweak);

    println!("{:?}", &dec);
}
