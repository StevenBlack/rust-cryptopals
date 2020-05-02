//
// The string:
//
// 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
//
// Should produce:
//
// SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
//

use hex;
use base64;

fn main() {
  let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
  let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

  println!("The hex value is: {}", hex);
  println!("The base64 output is: {}", hex_to_base64(hex));
  println!("The base64 output expected is: {}", expected);

}

fn hex_to_base64(h: &str) -> String {
    return base64::encode(hex::decode(h).unwrap());
}