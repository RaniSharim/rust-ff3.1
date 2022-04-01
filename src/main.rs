pub mod ff31;

fn main() {
    let x = ff31::FF31::new(&[1, 2, 3], 10);
    x.encrypt(&[1, 2, 3], &[0; 7]);
    println!("Hello, world!");
}
