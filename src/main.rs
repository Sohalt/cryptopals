fn main() {
    challenge_1()
}

fn challenge_1() {
    let hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"; // Hexadecimal input
    let expected_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    let bytes = hex_to_bytes(hex_string);
    let base64_string = bytes_to_base64(bytes);
    println!("Base64: {}", base64_string);
    println!("Success: {}", base64_string == expected_output)
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
