extern crate crypto;
extern crate rand;

use crypto::{aes, blockmodes, buffer, symmetriccipher};
use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};

use rand::{OsRng, Rng};

// Encrypt a buffer with the given key and iv using
// AES-256/CBC/Pkcs encryption.
fn encrypt(
  data: &[u8],
  key: &[u8],
  iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
  // Create an encryptor instance of the best performing
  // type available for the platform.
  let mut encryptor =
    aes::cbc_encryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

  let mut final_result = Vec::<u8>::new();
  let mut read_buffer = buffer::RefReadBuffer::new(data);
  let mut buffer = [0; 4096];
  let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

  loop {
    let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));

    final_result.extend(
      write_buffer
        .take_read_buffer()
        .take_remaining()
        .iter()
        .map(|&i| i),
    );

    match result {
      BufferResult::BufferUnderflow => break,
      BufferResult::BufferOverflow => {}
    }
  }

  Ok(final_result)
}

// Decrypts a buffer with the given key and iv using
// AES-256/CBC/Pkcs encryption.
fn decrypt(
  encrypted_data: &[u8],
  key: &[u8],
  iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
  let mut decryptor =
    aes::cbc_decryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

  let mut final_result = Vec::<u8>::new();
  let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
  let mut buffer = [0; 4096];
  let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

  loop {
    let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
    final_result.extend(
      write_buffer
        .take_read_buffer()
        .take_remaining()
        .iter()
        .map(|&i| i),
    );
    match result {
      BufferResult::BufferUnderflow => break,
      BufferResult::BufferOverflow => {}
    }
  }

  Ok(final_result)
}

fn main() {
  let cryptocurrency_data: &'static str = r#"{"wallet": "1NKRYhGFsx9ASY6mmnkxSw2MiUq2sdrvuE","privateKey": "Kzi94xyqMZhKodY3fX8tvXoV5WZ2fWVLGvQxjGosw31nAfAcNMKP"}"#;

  let mut key: [u8; 32] = [0; 32];
  let mut iv: [u8; 16] = [0; 16];

  let mut rng = OsRng::new().ok().unwrap();
  rng.fill_bytes(&mut key);
  rng.fill_bytes(&mut iv);

  let mut nested_encrypted_data: Vec<u8> = encrypt(cryptocurrency_data.as_bytes(), &key, &iv)
    .ok()
    .unwrap();

  for _ in 0..10 {
    nested_encrypted_data = encrypt(nested_encrypted_data.as_slice(), &key, &iv)
      .ok()
      .unwrap();
  }

  let mut nested_decrypted_data: Vec<u8> = nested_encrypted_data.clone();

  for _ in 0..11 {
    nested_decrypted_data = decrypt(nested_decrypted_data.as_slice(), &key, &iv)
      .ok()
      .unwrap();
  }

  println!(
    r#"
Key: {:?}
IV: {:?}
"#,
    key, iv
  );

  println!(
    r#"
"Original: {}",

"Encrypted: {:?}",

"Decrypted: {:?}"#,
    cryptocurrency_data,
    String::from_utf8_lossy(nested_encrypted_data.as_slice()),
    String::from_utf8(nested_decrypted_data.clone())
      .ok()
      .unwrap()
  );

  assert!(cryptocurrency_data.as_bytes() == nested_decrypted_data.as_slice());
}
