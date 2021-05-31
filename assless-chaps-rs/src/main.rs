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
use std::thread;
use std::sync::mpsc;

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

fn des_crypt(key: &[u8], clear: &[u8]) -> Vec<u8> {
  let exp_key = expand_des_key(&key);
  let cipher = Des::new_from_slice(&exp_key).unwrap();
  println!("{}",clear.len());
  let mut check = GenericArray::clone_from_slice(clear);
  cipher.encrypt_block(&mut check);
  return check.as_slice().to_vec();
}

fn check_hash(ntresponse: &Vec<u8>, challenge: &Vec<u8>, chunk: &[u8; 7], start: usize) 
  -> Result<(), ()>
{
  let ciphertext = &ntresponse[start .. start+8];
  let check = des_crypt(chunk,challenge);

  if &check == ciphertext {
    println!("[+] Found hash: {:?}",chunk);
    return Ok(());
  } else {
    return Err(());
  }
}

fn brute_twobytes(ntresponse: &Vec<u8>, challenge: &Vec<u8>) 
  -> Result<[u8; 2], ()>
{
  let no_threads = 4;
  let (tx, rx) = mpsc::channel();

  for j in 0..no_threads {
    let tx_thread = tx.clone();
    let ntresponse = ntresponse.clone();
    let challenge = challenge.clone();
    thread::spawn(move || {
      let ciphertext = &ntresponse[16 .. 24];
      let start: u16 = j*(65535/no_threads);
      let end: u16 = if j != no_threads { 
        (j+1) * (65535/no_threads)
      } else {
        ((j+1) * (65535/no_threads)) + 65535%no_threads
      };
      for i in start..=end {
        let mut candidate: Vec<u8> = Vec::with_capacity(8);
        candidate.extend_from_slice(&i.to_be_bytes());
        candidate.extend_from_slice(b"\x00\x00\x00\x00\x00");
        let check = des_crypt(&candidate,&challenge);

        if &check == ciphertext {
          println!("[+] Found in {} tries: {:02x}",i,i);
          tx_thread.send(Some(i)).unwrap();
          break;
        }
        // Check if it's been found and we should kill this thread
        // Otherwise just send a status message
        if i%1000 == 0 { if tx_thread.send(None).is_err() { break; }; };
      }
      //println!("{} ended",j);
    });
  }

  for recieved in rx {
    if recieved != None { 
      return Ok(recieved.unwrap().to_be_bytes());
    }
  }
  return Err(());
}

fn find_hashes(hashlist: &String, twobytes: &[u8; 2], ntresponse: &Vec<u8>, challenge: &Vec<u8>) {
  let connection = sqlite::open(hashlist).unwrap();
  let mut cursor = connection
    .prepare("select chunk1,chunk2 from hashes where twobytes=?")
    .unwrap()
    .into_cursor(); 
  let mut i = 0;

  cursor.bind(&[sqlite::Value::String(hex::encode(twobytes))]).unwrap();
  while let Some(hashes) = cursor.next().unwrap() {
    i += 1;
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

fn main() {
  let args: Vec<String> = env::args().collect();
  let challenge = <Vec<u8>>::from_hex(&args[1]).unwrap();
  let ntresponse = <Vec<u8>>::from_hex(&args[2]).unwrap();
  if let Ok(twobytes) = brute_twobytes(&ntresponse, &challenge) {
    find_hashes(&args[3], &twobytes, &ntresponse, &challenge);
  }
}
