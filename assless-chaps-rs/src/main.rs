extern crate des;
extern crate sqlite;
extern crate hex;

use std::env;
use hex::{FromHex};
use des::Des;
use des::cipher::{
    BlockEncrypt, NewBlockCipher,
    generic_array::GenericArray,
};

fn expand_des_key(key: &[u8]) -> Vec<u8> {
  let mut s: Vec<u8> = vec![b'\x00'; 8];
  s[0] = ((key[0] >> 1) & 0x7f) << 1;
  s[1] = ((key[0] & 0x01) << 6 | ((key[1] >> 2) & 0x3f)) << 1;
  s[2] = ((key[1] & 0x03) << 5 | ((key[2] >> 3) & 0x1f)) << 1;
  s[3] = ((key[2] & 0x07) << 4 | ((key[3] >> 4) & 0x0f)) << 1;
  s[4] = ((key[3] & 0x0f) << 3 | ((key[4] >> 5) & 0x07)) << 1;
  s[5] = ((key[4] & 0x1f) << 2 | ((key[5] >> 6) & 0x03)) << 1;
  s[6] = ((key[5] & 0x3f) << 1 | ((key[6] >> 7) & 0x01)) << 1;
  s[7] = (key[6] & 0x7f) << 1;
  return s; 
}

fn check_hash(ntresponse: &[u8; 24], challenge: &[u8; 8], chunk: &[u8; 7], start: usize) 
  -> Result<(), ()>
{
  let ciphertext = &ntresponse[start .. start+8];
  let key = expand_des_key(chunk);
  let cipher = Des::new_from_slice(&key).unwrap();
  let mut check = GenericArray::clone_from_slice(challenge);
  cipher.encrypt_block(&mut check);

  if check.as_slice() == ciphertext {
    println!("[+] Found hash: {:?}",chunk);
    return Ok(());
  } else {
    return Err(());
  }
}

fn brute_twobytes(ntresponse: &[u8; 24], challenge: &[u8; 8]) 
  -> Result<[u8; 2], ()>
{
  let ciphertext = &ntresponse[16 .. 24];
  for i in 0..=65535_u16 {
    let mut candidate: Vec<u8> = Vec::with_capacity(8);
    candidate.extend_from_slice(&i.to_be_bytes());
    candidate.extend_from_slice(b"\x00\x00\x00\x00\x00");
    let key = expand_des_key(&candidate);

    let cipher = Des::new_from_slice(&key).unwrap();
    let mut check = GenericArray::clone_from_slice(challenge);
    cipher.encrypt_block(&mut check);

    if check.as_slice() == ciphertext {
      println!("[+] Found in {} tries: {:02x}",i,i);
      return Ok(i.to_be_bytes());
    }
  }
  return Err(());
}

fn find_hashes(hashlist: &String, twobytes: &[u8; 2], ntresponse: &[u8; 24], challenge: &[u8; 8]) {
  let connection = sqlite::open(hashlist).unwrap();
  let mut cursor = connection
    .prepare("select rowid from hashes where twobytes=?")
    .unwrap()
    .into_cursor(); 

  let mut cursor2 = connection
    .prepare("select chunk1,chunk2 from hashes where rowid=?")
    .unwrap()
    .into_cursor(); 

  let mut i = 0;
  cursor.bind(&[sqlite::Value::String(hex::encode(twobytes))]).unwrap();
  while let Some(row) = cursor.next().unwrap() {
    i += 1;
    cursor2.bind(&[sqlite::Value::Integer(row[0].as_integer().unwrap())]).unwrap();
    if let Some(hashes) = cursor2.next().unwrap() {
      //hashes[0] - chunk1, hashes[1] - chunk2
      let chunk1 = <[u8; 7]>::from_hex(hashes[0].as_string().unwrap()).unwrap();
      if let Ok(()) = check_hash(&ntresponse, &challenge, &chunk1, 0) {
        println!("[-] Found after {} hashes.",i);
        let chunk2 = <[u8; 7]>::from_hex(hashes[1].as_string().unwrap()).unwrap();
        if let Ok(()) = check_hash(&ntresponse, &challenge, &chunk2, 8) {
          println!("[+] Full hash: {}{}{}",hashes[0].as_string().unwrap(),hashes[1].as_string().unwrap(),hex::encode(twobytes));
          break;
        }
      }
    }

  }
}

fn main() {
  let args: Vec<String> = env::args().collect();
  let challenge = <[u8; 8]>::from_hex(&args[1]).unwrap();
  let ntresponse = <[u8; 24]>::from_hex(&args[2]).unwrap();
  if let Ok(twobytes) = brute_twobytes(&ntresponse, &challenge) {
    find_hashes(&args[3], &twobytes, &ntresponse, &challenge);
  }
}
