//
//

use hex;
use base64;

fn main() {
  wrap(&challenge1);
  wrap(&challenge2);
}

fn hex_to_base64(h: &str) -> String {
    return base64::encode(hex::decode(h).unwrap());
}

fn hex_xor(h: &str, k: &str) -> String {
  let o: Vec<u8> = hex::decode(h).unwrap()
    .iter()
    .zip(hex::decode(k).unwrap().iter())
    .map(|(&x1, &x2)| x1 ^ x2)
    .collect();
  return hex::encode(o);
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

