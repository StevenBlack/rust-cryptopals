//
//

use hex;
use base64;
use std::str;
// extern crate regex;
use regex::Regex;

fn main() {
  wrap(&challenge1);
  wrap(&challenge2);
  wrap(&challenge3);
}

fn hex_to_base64(h: &str) -> String {
    return base64::encode(hex::decode(h).unwrap());
}

fn hex_xor(h: &str, k: &str) -> String {
  let o: Vec<u8> = hex::decode(h).unwrap()
    .iter()
    .zip(hex::decode(k).unwrap().iter().cycle())
    .map(|(&x1, &x2)| x1 ^ x2)
    .collect();
  return hex::encode(o);
}

fn challenge3() {
  println!("Challenge 3");
  // The hex encoded string:
  // 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
  // ... has been XOR'd against a single character. Find the key, decrypt the message.

  let hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
  println!("The hex is: {}", hex);
  println!("Possible plaintext:");


  // presume alphanumeric
  let re = Regex::new(r"[[:alpha:]]").unwrap();
  // presume at least one space
  let rs = Regex::new(r" ").unwrap();
  // presume vowel
  let rvo = Regex::new(r"[a,e,i,o,u,A,E,I,O,U]").unwrap();

  // presume no line feeds, carriage returns, or vertical tabs
  let rl = Regex::new(r"\n").unwrap();
  let rr = Regex::new(r"\r").unwrap();
  let rv = Regex::new(r"\v").unwrap();

  let mut count = 0;

  for kn in 1..=255 {
    let key = hex::encode([kn]).to_string();
    // hex::decode returns a rust Result<&str, Utf8Error>
    let res = hex::decode(hex_xor(hex, &key));
    let s = match res {
      Ok(v) => v,
      Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    };

    // check s for vowels
    // println!("{:?}", s);

    let result = String::from_utf8_lossy(&s);
    // checks
    if re.is_match(&result) && rvo.is_match(&result) && rs.is_match(&result) && !rl.is_match(&result) && !rr.is_match(&result) && !rv.is_match(&result) {
      count = count + 1;
      println!("key is: {}, output is: {}", &key, result);
    }
  }
  println!("Candidates found: {}", count);
}

fn challenge2() {
  println!("Challenge 2");
  // feed it the string:
  // 1c0111001f010100061a024b53535009181c
  // ... after hex decoding, and when XOR'd against:
  // 686974207468652062756c6c277320657965
  // ... should produce:
  // 746865206b696420646f6e277420706c6179

  let hex = "1c0111001f010100061a024b53535009181c";
  let key = "686974207468652062756c6c277320657965";
  let expected = "746865206b696420646f6e277420706c6179";
  let result = hex_xor(hex, key);
  assert_eq!(expected, result);

  println!("The hex is: {}", hex);
  println!("The key is: {}", key);
  println!("The XOR output is: {}", result);
  println!("The XOR output expected is: {}", expected);
}

fn challenge1() {
  println!("Challenge 1");
  // The string:
  // 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
  // Should produce:
  // SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

  let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
  let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
  let result = hex_to_base64(hex);
  assert_eq!(expected, result);

  println!("The hex value is: {}", hex);
  println!("The base64 output is: {}", result);
  println!("The base64 output expected is: {}", expected);
}

fn wrap(f: &dyn Fn()) {
  sep();
  f();
  sep()
}

fn sep() {
  println!("{}", "=====================".to_string());
}

