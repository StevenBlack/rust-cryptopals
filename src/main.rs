// use hex;
// use regex::Regex;
use indoc::indoc;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

mod crpt {
  use base64;
  use regex::Regex;

  pub struct KV {
    pub key: u8,
    pub value: String,
  }

  pub fn plausible_text(hex: &str) -> Vec<KV> {
    let mut ret_vec = Vec::new();
    // presume alphanumeric
    let ralpha = Regex::new(r"[[:alpha:]]").unwrap();
    // presume at least one space
    let rs = Regex::new(r" ").unwrap();
    // presume vowel
    let rvowel = Regex::new(r"[a,e,i,o,u,A,E,I,O,U]").unwrap();
    // presume no line feeds, carriage returns, or vertical tabs
    // let rl = Regex::new(r"\n").unwrap();
    let rr = Regex::new(r"\r").unwrap();
    let rv = Regex::new(r"\v").unwrap();

    for kn in 0..=255 {
      let key = hex::encode([kn]).to_string();
      // hex::decode returns a rust Result<&str, Utf8Error>
      let res = hex::decode(hex_xor(hex, &key));
      let s = match res {
        Ok(v) => v,
        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
      };

      // discard if any u8 element is above 128
      if s.iter().max().unwrap() > &127u8 {
        break;
      }

      let result = String::from_utf8_lossy(&s);
      // checks
      if ralpha.is_match(&result)
        && rvowel.is_match(&result)
        && rs.is_match(&result)
        // && !rl.is_match(&result)
        && !rr.is_match(&result)
        && !rv.is_match(&result)
      {
        let foo = KV {
          key: kn,
          value: result.to_string(),
        };
        ret_vec.push(foo);
      }
    }
    return ret_vec;
  }

  pub fn encrypt_to_hex(key: String, message: String) -> String {
    let vecu8: Vec<u8> = message
      .into_bytes()
      .iter()
      .zip(key.into_bytes().iter().cycle())
      .map(|(&x1, &x2)| x1 ^ x2)
      .collect();
    return hex::encode(vecu8);
  }

  // hex_to_base64 takes a hex str and returns a base64 String.
  pub fn hex_to_base64(h: &str) -> String {
    return base64::encode(hex::decode(h).unwrap());
  }

  // hex_xor takes a hex str and a hey str and returns the xor as a string
  pub fn hex_xor(h: &str, k: &str) -> String {
    let o: Vec<u8> = hex::decode(h)
      .unwrap()
      .iter()
      .zip(hex::decode(k).unwrap().iter().cycle())
      .map(|(&x1, &x2)| x1 ^ x2)
      .collect();
    return hex::encode(o);
  }
}

fn main() {
  wrap(&challenge1, 0);
  wrap(&challenge2, 0);
  wrap(&challenge3, 0);
  wrap(&challenge4, 0);
  wrap(&challenge5, 0);
  wrap(&challenge6prelim, 0);
  wrap(&challenge6, 1);
}

fn challenge6() {
  use hamming::distance;
  // step 1: load the file into a string
  // read the file line by line and consolidate
  let mut ciphertext: String = "".to_string();
  if let Ok(lines) = read_lines("./files/challenge6.txt") {
    // Consumes the iterator, returns an (Optional) String
    for l in lines {
      if let Ok(line) = l {
        ciphertext.push_str(&line)
      }
    }
  }
  // step 2: Take two consecutive KeyLength chunks, calculate the distance between them
  let cipherbites = ciphertext.into_bytes();
  let mut key_length: i8 = 0;
  for kl in 1..=100 {
    let mut iter = cipherbites.chunks_exact(kl);
    let chunk1 = iter.next().unwrap();
    let chunk2 = iter.next().unwrap();
    let dist: u64 = distance(chunk1, chunk2);
    let avg = (dist / (kl as u64)) as f32;
    // println!("key length: {} - avg distance: {:?}", kl, avg);
    println!("{:.4}", avg);
  }
}

fn challenge6prelim() {
  use hamming::distance;
  println!("Challenge 6 preliminary");
  let s1 = b"this is a test";
  let s2 = b"wokka wokka!!!";
  assert_eq!(distance(s1, s2), 37);
}

fn challenge5() {
  println!("Challenge 5");
  // feed it the string:
  // Burning 'em, if you ain't quick and nimble
  // I go crazy when I hear a cymbal
  // ... after XOR'd with `iCE`
  // ... should produce:
  // 0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
  // a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

  let msg = indoc!(
    r#"
  Burning 'em, if you ain't quick and nimble 
  I go crazy when I hear a cymbal"#
  )
  .to_string();
  let key = "ICE".to_string();
  let expected = indoc!(
    r#"
  0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
  a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"#
  )
  .to_string();
  let result = crpt::encrypt_to_hex(key.clone(), msg.clone());
  assert_eq!(expected, result);

  println!("The hex is: {}", msg.clone());
  println!("The key is: {}", key.clone());
  println!("The XOR output is: {}", result);
  println!("The XOR output expected is: {}", expected);
}

fn challenge4() {
  println!("Challenge 4");
  // read the file line by line
  if let Ok(lines) = read_lines("./files/challenge4.txt") {
    // Consumes the iterator, returns an (Optional) String
    for line in lines {
      if let Ok(ip) = line {
        println!("ct --> {}", ip);
        let resultats = crpt::plausible_text(&ip);
        for result in resultats.iter() {
          println!("key is: {}, output is: {}", result.key, result.value);
        }
      }
    }
  }
}

fn challenge3() {
  println!("Challenge 3");
  // The hex encoded string:
  // 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
  // ... has been XOR'd against a single character. Find the key, decrypt the message.

  let hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
  println!("The hex is: {}", hex);
  println!("Possible plaintext:");

  let resultats = crpt::plausible_text(&hex);
  for result in resultats.iter() {
    println!("key is: {}, output is: {}", result.key, result.value);
  }

  println!("Candidates found: {}", resultats.len());
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
  let result = crpt::hex_xor(hex, key);
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
  let result = crpt::hex_to_base64(hex);
  assert_eq!(expected, result);

  println!("The hex value is: {}", hex);
  println!("The base64 output is: {}", result);
  println!("The base64 output expected is: {}", expected);
}

fn wrap(f: &dyn Fn(), run: i8) {
  if run == 0 {
    return;
  }
  sep();
  f();
  sep()
}

fn sep() {
  println!("{}", "=====================".to_string());
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
  P: AsRef<Path>,
{
  let file = File::open(filename)?;
  Ok(io::BufReader::new(file).lines())
}
