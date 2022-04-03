use aes::cipher::KeyInit;
use aes::cipher::{generic_array::GenericArray, BlockEncrypt};
use aes::{Aes128, Aes192, Aes256};

use num_bigint::{BigInt, Sign, ToBigInt};
use std::ops::{Add, Div, Mul, Sub};

enum Cipher {
    AES128(Aes128),
    AES192(Aes192),
    AES256(Aes256),
}

impl Cipher {
    fn ciph(&self, x: &mut [u8; 16]) {
        let block = GenericArray::from_mut_slice(x);
        match &self {
            Cipher::AES128(cipher) => cipher.encrypt_block(block),
            Cipher::AES192(cipher) => cipher.encrypt_block(block),
            Cipher::AES256(cipher) => cipher.encrypt_block(block)
        }        
    }
}

pub struct FF31<'a> {
    radix: u32,
    alphabet: &'a str,
    min: usize,
    max: usize,
    ciph_alg: Cipher,
}

impl<'a> FF31<'a> {
    pub fn new(key: &'a [u8], alphabet: &'a str) -> Self {
        let radix = alphabet.len();
        let max = (192f64 / (radix as f64).log2()).floor() as usize;


        let ciph_alg = match key.len() {
            16 => { 
                let key = GenericArray::from_slice(key);
                let cipher = Aes128::new(key); 
                Cipher::AES128(cipher)
            }
            24 => { 
                let key = GenericArray::from_slice(key);
                let cipher = Aes192::new(key); 
                Cipher::AES192(cipher)
            }
            32 => { 
                let key = GenericArray::from_slice(key);
                let cipher = Aes256::new(key); 
                Cipher::AES256(cipher)

            }
            _ => panic!("wrong key size provided")
       };


        FF31 {
            alphabet,
            radix: radix as u32,
            min: 7,
            max,
            ciph_alg,
        }
    }

    fn enc_from_string(&self, plain_text: &'a str) -> Vec<u32> {
        let mut res = Vec::with_capacity(plain_text.len());
        plain_text.chars().for_each(|c| {
            for (i, ac) in self.alphabet.char_indices() {
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
        decrypted_str.iter().for_each(|d| {
            res.push(self.alphabet.chars().nth(*d as usize).unwrap());
        });
        res
    }

    pub fn encrypt(&self, plain_text: &'a str, tweak: &[u8; 7]) -> String {
        self.enc_to_string(&self.cipher(&self.enc_from_string(plain_text), tweak, true))
    }

    pub fn decrypt(&self, cipher_text: &'a str, tweak: &[u8; 7]) -> String {
        self.enc_to_string(&self.cipher(&self.enc_from_string(cipher_text), tweak, false))
    }

    fn cipher(&self, text: &[u32], tweak: &[u8; 7], is_enc: bool) -> Vec<u32> {
        if text.len() < self.min {
            panic!("text too small");
        }

        if text.len() > self.max {
            panic!("text too large");
        }
        
        // step 1
        let u = text.len() / 2;
        let v = text.len() - u;

        // step 2
        let mut a: Vec<u32>;
        let mut b: Vec<u32>;

        if is_enc {
            a = Vec::from(&text[..u]);
            b = Vec::from(&text[u..]);
        } else {
            b = Vec::from(&text[..u]);
            a = Vec::from(&text[u..]);
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

            p[..4].copy_from_slice(&w[..4]);

            if is_enc {
                p[3] ^= i as u8;
            } else {
                p[3] ^= (7 - i) as u8;
            }

            let c = to_bigint(&revs(&b), self.radix);

            let nb = c.to_bytes_be().1;

            let nb_len = nb.len();
            if nb_len >= 12 {
                p[4..].copy_from_slice(&nb[..12])
            } else {
                let p_len = p.len();
                p[4..p_len - nb_len].fill(0);
                p[p_len - nb_len..].copy_from_slice(&nb[..])
            }

            p.reverse();

            self.ciph_alg.ciph(&mut p);

            p.reverse();

            let y = BigInt::from_bytes_be(Sign::Plus, &p);
            let mut c = to_bigint(&revs(&a), self.radix);

            if is_enc {
                c = c.add(y);
            } else {
                c = c.sub(y);
            }

            let mut r = self.radix.to_bigint().unwrap();
            r = r.pow(m);

            c = c.modpow(&(1i32.to_bigint().unwrap()), &r);

            a = b;
            b = to_rev_str(c, self.radix, u);
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

fn revs(x: &[u32]) -> Vec<u32> {
    let mut y = x.to_vec();
    y.reverse();
    y
}

fn to_rev_str(mut x: BigInt, radix: u32, m: usize) -> Vec<u32> {
    let mut res = Vec::with_capacity(m);

    let e = 1u32.to_bigint().unwrap();
    let r = radix.to_bigint().unwrap();
    let z = 0u32.to_bigint().unwrap();

    while x > z {
        let d = x.modpow(&e, &r);

        if d == z {
            res.push(0);
        } else {
            res.push(d.to_u32_digits().1[0]);
        }

        x = x.div(radix);
    }

    while res.len() < m {
        res.push(0);
    }

    res
}

fn to_bigint(n: &[u32], radix: u32) -> BigInt {
    let mut b = BigInt::from_bytes_be(Sign::NoSign, &[0u8]);

    for d in n.iter() {
        b = b.mul(radix);
        b = b.add(d);
    }

    b
}
