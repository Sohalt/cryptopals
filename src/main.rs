use std::collections::BinaryHeap;
use std::fs;
use std::str;

fn main() {
    challenge_1();
    challenge_2();
    challenge_3();
    challenge_4();
    challenge_5();
}

fn challenge_1() {
    let hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"; // Hexadecimal input
    let expected_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    let bytes = hex_to_bytes(hex_string);
    let base64_string = bytes_to_base64(bytes);
    println!("Challenge 1");
    println!("Base64: {}", base64_string);
    println!("Success: {}", base64_string == expected_output)
}

fn challenge_2() {
    let hex1 = "1c0111001f010100061a024b53535009181c";
    let hex2 = "686974207468652062756c6c277320657965";
    let expected_output = "746865206b696420646f6e277420706c6179";
    let xored_bytes = xor_bytes(&hex_to_bytes(&hex1), &hex_to_bytes(&hex2));
    println!("Challenge 2");
    println!("xor: {}", bytes_to_hex(&xored_bytes));
    println!("Success: {}", expected_output == bytes_to_hex(&xored_bytes));
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
struct Decrypted {
    score: u32,
    key: u8,
    plaintext: Box<String>,
}

fn score(s: &str) -> u32 {
    s.chars().filter(|c| *c == ' ').count() as u32
}

fn decrypt_xor_single(key: u8, cyphertext: &str) -> Decrypted {
    let input_bytes = hex_to_bytes(cyphertext);
    let xor = repeated_xor_cipher(&[key], &input_bytes);
    match String::from_utf8(xor) {
        Ok(plaintext) => {
            let score = score(&plaintext);
            Decrypted {
                score,
                key,
                plaintext: Box::new(plaintext),
            }
        }
        Err(_) => Decrypted {
            score: 0,
            key,
            plaintext: Box::new(String::from("")),
        },
    }
}

fn brute_force(cypthertext: &str) -> Decrypted {
    let mut possibilites = BinaryHeap::new();
    (b'A'..=b'Z')
        .chain(b'a'..=b'z')
        .chain(b'0'..=b'9')
        .for_each(|key| {
            possibilites.push(decrypt_xor_single(key, &cypthertext));
        });
    possibilites.pop().unwrap()
}

fn challenge_3() {
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let best_guess = brute_force(input);
    println!("Challenge 3");
    println!("key: {}, text: {}", best_guess.key, best_guess.plaintext);
}

fn challenge_4() {
    let input = fs::read_to_string("4.txt").unwrap();
    let mut possibilites = BinaryHeap::new();
    input.lines().for_each(|line| {
        let d = brute_force(line);
        println!("{}", d.plaintext);
        possibilites.push(d);
    });
    let best_guess = possibilites.pop().unwrap();
    println!("Challenge 4");
    println!(
        "key: {}, text: {}",
        best_guess.key as char, best_guess.plaintext
    );
}

fn string_to_bytes(s: &str) -> Vec<u8> {
    s.chars().map(|c| c as u8).collect()
}

fn challenge_5() {
    let input = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
    let key = "ICE";
    let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    let encrypted = bytes_to_hex(&repeated_xor_cipher(
        &string_to_bytes(key),
        &string_to_bytes(input),
    ));
    println!("Challenge 5");
    println!("Encrypted: {}", &encrypted);
    println!("Success: {}", expected == encrypted);
}

fn xor_bytes(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    b1.iter().zip(b2.iter()).map(|(x, y)| x ^ y).collect()
}

fn repeated_xor_cipher(key: &[u8], cyphertext: &[u8]) -> Vec<u8> {
    let mut i = 0;
    let mut out = Vec::with_capacity(cyphertext.len());
    while i < cyphertext.len() {
        out.push(key[i % key.len()] ^ cyphertext[i]);
        i = i + 1;
    }
    out
}

fn digit_to_char(d: u8) -> char {
    if d < 10 {
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
