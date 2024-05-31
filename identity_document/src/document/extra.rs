use identity_verification::jwk::Jwk;
use identity_verification::jws::{JwsAlgorithm, JwsVerifier};
use crate::verifiable::JwsVerificationOptions;
use crate::error::Result;
use crate::utils::DIDUrlQuery;
use crate::error::Error;
use std::str::FromStr;
use std::time::Instant;
use identity_verification::jws::VerificationInput;

use super::CoreDocument;

pub trait PlainSig {
    fn verify_sig<'jws, T: JwsVerifier>(
        &self,
        kid: &[u8],
        sig: &[u8],
        signing_input: &[u8],
        //detached_payload: Option<&'jws [u8]>,
        signature_verifier: &T,
        options: &JwsVerificationOptions,
      ) -> Result<()>;
}

impl PlainSig for CoreDocument {
  fn verify_sig<'jws, T: JwsVerifier>(
      &self,
      kid: &[u8],
      sig: &[u8],
      signing_input: &[u8],
      //detached_payload: Option<&'jws [u8]>,
      signature_verifier: &T,
      options: &JwsVerificationOptions,
    ) -> Result<()> {
      /* let validation_item = Decoder::new()
    .decode_compact_serialization(jws.as_bytes(), detached_payload)
    .map_err(Error::JwsVerificationError)?; */

  /* let nonce: Option<&str> = options.nonce.as_deref();
  // Validate the nonce
  if validation_item.nonce() != nonce {
    return Err(Error::JwsVerificationError(
      identity_verification::jose::error::Error::InvalidParam("invalid nonce value"),
    ));
  }*/

  let method_url_query: DIDUrlQuery<'_> = std::str::from_utf8(kid).unwrap().into();

  let t = Instant::now();
  
  let public_key: &Jwk = self
    .resolve_method(method_url_query, options.method_scope)
    .ok_or(Error::MethodNotFound)?
    .data()
    .try_public_key_jwk()
    .map_err(Error::InvalidKeyMaterial)?;
  
  let elapsed = t.elapsed();
  println!("time verification input = {} micro", elapsed.as_micros());  

  // Construct verification input
  let input = VerificationInput {
    alg: JwsAlgorithm::from_str(public_key.alg().ok_or(Error::MethodNotFound)?).map_err(|_| Error::MethodNotFound)?,
    signing_input: signing_input.to_vec().into_boxed_slice(),
    decoded_signature: sig.to_vec().into_boxed_slice(),
  };
  
  signature_verifier
    .verify(input, public_key)
    .map_err(|_| Error::MethodNotFound)
    }
}