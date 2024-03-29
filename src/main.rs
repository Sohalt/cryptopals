use std::collections::BinaryHeap;
use std::iter;
use std::str;

fn main() {
    challenge_1();
    challenge_2();
    challenge_3();
}

fn challenge_1() {
    let hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"; // Hexadecimal input
    let expected_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    let bytes = hex_to_bytes(hex_string);
    let base64_string = bytes_to_base64(bytes);
    println!("Base64: {}", base64_string);
    println!("Success: {}", base64_string == expected_output)
}

fn challenge_2() {
    let hex1 = "1c0111001f010100061a024b53535009181c";
    let hex2 = "686974207468652062756c6c277320657965";
    let expected_output = "746865206b696420646f6e277420706c6179";
    let xored_bytes = xor_bytes(&hex_to_bytes(&hex1), &hex_to_bytes(&hex2));
    println!("xor: {}", bytes_to_hex(&xored_bytes));
    println!("Success: {}", expected_output == bytes_to_hex(&xored_bytes));
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
struct Decrypted {
    score: u32,
    key: char,
    plaintext: Box<String>,
}

fn score(s: &str) -> u32 {
    s.chars().filter(|c| *c == ' ').count() as u32
}

fn challenge_3() {
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let input_bytes = hex_to_bytes(input);
    let mut possibilites = BinaryHeap::new();
    (b'A'..=b'Z').for_each(|key| {
        let key_bytes = &iter::repeat(key)
            .take(input_bytes.len())
            .collect::<Vec<u8>>();
        let plaintext = Box::new(String::from_utf8(xor_bytes(key_bytes, &input_bytes)).unwrap());
        let score = score(&plaintext);
        possibilites.push(Decrypted {
            score,
            key: key as char,
            plaintext,
        });
    });
    let best_guess = possibilites.pop().unwrap();
    println!("key: {}, text: {}", best_guess.key, best_guess.plaintext);
}

fn xor_bytes(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    b1.iter().zip(b2.iter()).map(|(x, y)| x ^ y).collect()
}

fn digit_to_char(d: u8) -> char {
    if 0 <= d && d < 10 {
        (('0' as u8) + d) as char
    } else {
        (('a' as u8) + d - 10) as char
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::new();
    for byte in bytes.iter() {
        let upper = digit_to_char(byte >> 4);
        let lower = digit_to_char(byte & 0xF);
        s.push(upper);
        s.push(lower);
    }
    s
}

fn hex_to_bytes(hex_string: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut buffer = 0;
    let mut count = 0;

    for digit in hex_string.chars() {
        buffer <<= 4;
        buffer |= match digit {
            '0'..='9' => digit as u8 - b'0',
            'a'..='f' => digit as u8 - b'a' + 10,
            'A'..='F' => digit as u8 - b'A' + 10,
            _ => panic!("Non hex character"),
        };

        count += 1;
        if count == 2 {
            bytes.push(buffer);
            buffer = 0;
            count = 0;
        }
    }

    bytes
}

fn bytes_to_base64(bytes: Vec<u8>) -> String {
    let base64_chars: Vec<char> =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            .chars()
            .collect();
    let mut base64_string = String::new();

    let mut i = 0;
    while i < bytes.len() {
        let byte1 = bytes[i];
        let byte2 = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
        let byte3 = if i + 2 < bytes.len() { bytes[i + 2] } else { 0 };

        base64_string.push(base64_chars[(byte1 >> 2) as usize]);
        base64_string.push(base64_chars[(((byte1 & 0b11) << 4) | (byte2 >> 4)) as usize]);
        base64_string.push(base64_chars[(((byte2 & 0b1111) << 2) | (byte3 >> 6)) as usize]);
        base64_string.push(base64_chars[(byte3 & 0b111111) as usize]);
        i += 3;
    }
    //fixup padding
    match bytes.len() % 3 {
        2 => {
            base64_string.pop();
            base64_string.push('=');
        }
        1 => {
            base64_string.pop();
            base64_string.pop();
            base64_string.push('=');
            base64_string.push('=')
        }
        _ => {}
    }
    base64_string
}
