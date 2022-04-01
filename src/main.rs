pub mod ff31;

fn main() {
    let x = ff31::FF31::new(&[1, 2, 3], 10);
    let tweak = [0; 7];

    let enc = x.encrypt(&[1, 2, 3], &tweak);
    let dec = x.decrypt(&enc, &tweak);

    println!("{:?}", &dec);
}
