fn main() {
    let c: u8 = u8::from_str_radix("A", 16).unwrap();
    print!("{:?}", c)
}
