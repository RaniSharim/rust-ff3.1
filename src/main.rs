use aes::Aes128;

pub mod ff31;

fn main() {
    // abcdefghijklmnopqrstuvwxyz
    let mut key = [
        0xef, 0x43, 0x59, 0xd8, 0xd5, 0x80, 0xaa, 0x4f, 0x7f, 0x03, 0x6d, 0x6f, 0x04, 0xfc, 0x6a,
        0x94,
    ];
    key.reverse();

    let x = ff31::FF31::<Aes128>::new(&key, "0123456789");
    let tweak = [0; 7];

    let enc = x.encrypt("890121234567890000", &tweak);
    println!("{:?}", &enc);

    // let dec = x.decrypt(&enc, &tweak);

    // println!("{:?}", &dec);

    // let mut enc = cbc::Encryptor::<Aes128>::new(
    //     &GenericArray::from([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    //     &GenericArray::from([0u8; 16]),
    // );

    // let mut x: [u8; 16] = [205, 129, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    // let block = GenericArray::from_mut_slice(&mut x);

    // enc.encrypt_block_mut(block);

    // println!("{:?}", &x);
}
