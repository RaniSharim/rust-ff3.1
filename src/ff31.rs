use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;

use num_bigint::{BigUint, ToBigUint};
use std::ops::{Add, Sub};
pub struct FF31<'a> {
    key: &'a [u8],
    radix: u32,
    alphabet: &'a str,
    min: u32,
    max: u32,
}

impl<'a> FF31<'a> {
    pub fn new(key: &'a [u8], alphabet: &'a str) -> Self {
        FF31 {
            key,
            alphabet,
            radix: alphabet.len() as u32,
            min: 2,
            max: 10,
        }
    }

    fn enc_from_string(&self, plain_text: &'a str) -> Vec<u32> {
        let mut res = Vec::with_capacity(plain_text.len());
        plain_text.chars().for_each(|c|{
            for (i,ac) in self.alphabet.char_indices() {
                if c == ac {
                    res.push(i as u32);
                    break;
                }
            }
        });
        res
    }
    
    fn enc_to_string(&self, decrypted_str: &[u32]) -> String {
        let mut res = String::with_capacity(decrypted_str.len());
        decrypted_str.into_iter().for_each(|d| {
            res.push(self.alphabet.chars().nth(*d as usize).unwrap());
        });
        res
    }

    pub fn encrypt(&self, plain_text: &'a str, tweak: &[u8; 7]) -> Vec<u32> {
        self.cipher(&self.enc_from_string(plain_text), tweak, true)
    }

    pub fn decrypt(&self, cipher_text: &[u32], tweak: &[u8; 7]) -> String {
        self.enc_to_string(&self.cipher(cipher_text, tweak, false))
    }

    fn cipher(&self, plain_text: &[u32], tweak: &[u8; 7], is_enc: bool) -> Vec<u32> {
        // step 1
        let u = plain_text.len() / 2;
        let v = plain_text.len() - u;

        // step 2
        let mut a: Vec<u32>;
        let mut b: Vec<u32>;

        if is_enc {
            a = Vec::from(&plain_text[..u]);
            b = Vec::from(&plain_text[u..]);
        } else {
            b = Vec::from(&plain_text[..u]);
            a = Vec::from(&plain_text[u..]);
        }

        // step 3
        let t_l = [tweak[0], tweak[1], tweak[2], tweak[3] & 0xf0];
        let t_r = [tweak[4], tweak[5], tweak[6], (tweak[3] & 0xf0) << 4];

        // step 4
        let mut p = [0u8; 16];
        for i in 0..8 {
            let mut m = u as u32;
            let mut w = t_r;

            if (is_enc && i % 2 == 0) || (!is_enc && i % 2 == 1) {
                m = v as u32;
                w = t_l;
            }

            p[..3].copy_from_slice(&w[..3]);

            if is_enc {
                p[3] ^= i as u8;
            } else {
                p[3] ^= (7 - i) as u8;
            }

            let nb = to_bytes(revs(&b));

            if nb.len() >= 12 {
                p[4..].copy_from_slice(&nb[..12])
            } else {
                p[4..].copy_from_slice(&nb[..])
            }

            p.reverse();
            ciph(&mut p, self.key);
            p.reverse();

            let y = BigUint::from_bytes_be(&p);
            let mut c = BigUint::from_bytes_be(&to_bytes(revs(&a)));

            if is_enc {
                c = c.add(y);
            } else {
                c = c.sub(y);
            }

            let r = self.radix.to_biguint().unwrap();
            r.pow(m);
            c = c.modpow(&(1i32.to_biguint().unwrap()), &r);
            a = b;
            let s = to_str(&c);
            let revs = revs(&s);
            b = revs.to_vec();
        }

        if is_enc {
            a.extend(b);
            a
        } else {
            b.extend(a);
            b
        }
    }
}

fn ciph(x: &mut [u8; 16], k: &[u8]) {
    let key = GenericArray::from_slice(k);
    let block = GenericArray::from_mut_slice(x);

    let cipher = Aes128::new(key);
    cipher.encrypt_block(block);
}

fn revs(x: &[u32]) -> Vec<u32> {
    let mut y = x.to_vec();
    y.reverse();
    y
}

fn to_bytes(x: Vec<u32>) -> Vec<u8> {
    let mut res = Vec::with_capacity(x.len() * 4);
    x.into_iter().for_each(|u| {
        res.extend_from_slice(&u.to_be_bytes());
    });
    res
}

fn from_bytes(x: &[u8]) -> Vec<u32> {
    let mut res = Vec::new();
    x.chunks_exact(4).for_each(|b| {
        let mut be: [u8; 4] = [0u8; 4];
        be.copy_from_slice(b);
        res.push(u32::from_be_bytes(be));
    });

    res
}

fn to_str(x: &BigUint) -> Vec<u32> {
    from_bytes(&x.to_bytes_be())
}
