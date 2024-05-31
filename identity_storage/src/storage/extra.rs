use super::JwkStorageDocumentError as Error;
use identity_document::document::CoreDocument;
use identity_iota_core::IotaDocument;
use async_trait::async_trait;
use identity_verification::{jwk::Jwk, jws::JwsAlgorithm, MethodScope};
use crate::ed25519::expand_secret_jwk;
use crate::{JwkStorage, JwsSignatureOptions, KeyId, KeyIdStorage, KeyType, Storage, StorageResult};
use crate::key_storage::JwkGenOutput;
use identity_verification::VerificationMethod;
use crate::key_id_storage::MethodDigest;
use identity_did::DIDUrl;
use crate::extra2::JwkStorageWithPrivateKey;

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
pub trait JwkDocumentExtra {

/// Generate method with Jwk attached
async fn generate_method_with_jwk<K, I>(
    &mut self,
    storage: &Storage<K, I>,
    key_type: KeyType,
    alg: JwsAlgorithm,
    fragment: Option<&str>,
    scope: MethodScope,
) -> StorageResult<(Jwk, String)>
where
  K: JwkStorageWithPrivateKey,
  I: KeyIdStorage;
}

/// Attempt to revert key generation. If this succeeds the original `source_error` is returned,
/// otherwise [`JwkStorageDocumentError::UndoOperationFailed`] is returned with the `source_error` attached as
/// `source`.
async fn try_undo_key_generation<K, I>(storage: &Storage<K, I>, key_id: &KeyId, source_error: Error) -> Error
where
  K: JwkStorage,
  I: KeyIdStorage,
{
  // Undo key generation
  if let Err(err) = <K as JwkStorage>::delete(storage.key_storage(), key_id).await {
    Error::UndoOperationFailed {
      message: format!("unable to delete stray key with id: {}", &key_id),
      source: Box::new(source_error),
      undo_error: Some(Box::new(Error::KeyStorageError(err))),
    }
  } else {
    source_error
  }
}

macro_rules! generate_method_for_document_type {
    ($t:ty, $name:ident) => {
      async fn $name<K, I>(
        document: &mut $t,
        storage: &Storage<K, I>,
        key_type: KeyType,
        alg: JwsAlgorithm,
        fragment: Option<&str>,
        scope: MethodScope,
      ) -> StorageResult<(Jwk, String)>
      where
        K: JwkStorageWithPrivateKey,
        I: KeyIdStorage,
      {
        let JwkGenOutput { key_id, jwk } = <K as JwkStorageWithPrivateKey>::generate_with_private_key(&storage.key_storage(), key_type, alg)
          .await
          .map_err(Error::KeyStorageError)?;
        
        let public_jwk: Jwk = jwk.to_public().expect("should only panic if kty == oct");

        // Produce a new verification method containing the generated JWK. If this operation fails we handle the error
        // by attempting to revert key generation before returning an error.
        let method: VerificationMethod = {
          match VerificationMethod::new_from_jwk(document.id().clone(), public_jwk.clone(), fragment)
            .map_err(Error::VerificationMethodConstructionError)
          {
            Ok(method) => method,
            Err(source) => {
              return Err(try_undo_key_generation(storage, &key_id, source).await);
            }
          }
        };

        // Extract data from method before inserting it into the DID document.
        let method_digest: MethodDigest = MethodDigest::new(&method).map_err(Error::MethodDigestConstructionError)?;
        let method_id: DIDUrl = method.id().clone();

        // The fragment is always set on a method, so this error will never occur.
        let fragment: String = method_id
          .fragment()
          .ok_or(identity_verification::Error::MissingIdFragment)
          .map_err(Error::VerificationMethodConstructionError)?
          .to_owned();

        // Insert method into document and handle error upon failure.
        if let Err(error) = document
          .insert_method(method, scope)
          .map_err(|_| Error::FragmentAlreadyExists)
        {
          return Err(try_undo_key_generation(storage, &key_id, error).await);
        };
  
        // Insert the generated `KeyId` into storage under the computed method digest and handle the error if the
        // operation fails.
        if let Err(error) = <I as KeyIdStorage>::insert_key_id(&storage.key_id_storage(), method_digest, key_id.clone())
          .await
          .map_err(Error::KeyIdStorageError)
        {
          // Remove the method from the document as it can no longer be used.
          let _ = document.remove_method(&method_id);
          return Err(try_undo_key_generation(storage, &key_id, error).await);
        }
  
        Ok((jwk, fragment))
      }
    };
}

generate_method_for_document_type!(IotaDocument, generate_method_iota_document);
#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl JwkDocumentExtra for IotaDocument {
    async fn generate_method_with_jwk<K, I>(
        &mut self,
        storage: &Storage<K, I>,
        key_type: KeyType,
        alg: JwsAlgorithm,
        fragment: Option<&str>,
        scope: MethodScope,
      ) -> StorageResult<(Jwk, String)>
      where
        K: JwkStorageWithPrivateKey,
        I: KeyIdStorage,
      {
        generate_method_iota_document(self, storage, key_type, alg, fragment, scope).await
      }
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
pub trait CreatePlainSig {
      async fn create_sig<K, I>(
        &self,
        storage: &Storage<K, I>,
        privkey: &Jwk,
        fragment: &str,
        payload: &[u8],
        options: &JwsSignatureOptions,
      ) -> StorageResult<Vec<u8>>
      where
        K: JwkStorageWithPrivateKey,
        I: KeyIdStorage;
}

#[cfg_attr(not(feature = "send-sync-storage"), async_trait(?Send))]
#[cfg_attr(feature = "send-sync-storage", async_trait)]
impl CreatePlainSig for CoreDocument {
    async fn create_sig<K, I>(
        &self,
        storage: &Storage<K, I>,
        privkey: &Jwk,
        fragment: &str,
        payload: &[u8],
        options: &JwsSignatureOptions,
      ) -> StorageResult<Vec<u8>>
      where
        K: JwkStorageWithPrivateKey,
        I: KeyIdStorage { 
        let secret_key = expand_secret_jwk(privkey).map_err(Error::KeyStorageError)?;
        let signature = secret_key.sign(payload).to_bytes().to_vec();
        //let key_id = <K as JwkStorage>::insert(&storage.key_storage(), privkey.clone()).await.map_err(Error::KeyStorageError)?;
        // Obtain the method corresponding to the given fragment.
        let method: &VerificationMethod = self.resolve_method(fragment, None).ok_or(Error::MethodNotFound)?;
        /* let MethodData::PublicKeyJwk(ref jwk) = method.data() else {
          return Err(Error::NotPublicKeyJwk);
        };
      */
      
        // Get the key identifier corresponding to the given method from the KeyId storage.
        //let method_digest: MethodDigest = MethodDigest::new(method).map_err(Error::MethodDigestConstructionError)?;
        //<I as KeyIdStorage>::insert_key_id(storage.key_id_storage(), method_digest.clone(), KeyId::new(keyid)).await.map_err(Error::KeyIdStorageError)?;
      
        //let key_id = <I as KeyIdStorage>::get_key_id(storage.key_id_storage(), &method_digest)
        //  .await
        //  .map_err(Error::KeyIdStorageError)?;
      
        // Extract Compact JWS encoding options.
        /* let encoding_options: CompactJwsEncodingOptions = if !options.detached_payload {
          // We use this as a default and don't provide the extra UrlSafe check for now.
          // Applications that require such checks can easily do so after JWS creation.
          CompactJwsEncodingOptions::NonDetached {
            charset_requirements: CharSet::Default,
          }
        } else {
          CompactJwsEncodingOptions::Detached
        }; */
      
        /* let jws_encoder: CompactJwsEncoder<'_> = CompactJwsEncoder::new_with_options(payload, &header, encoding_options)
          .map_err(|err| Error::EncodingError(err.into()))?; */
        //let public_jwk: Jwk = privkey.to_public().expect("should only panic if kty == oct");
        /* let signature = <K as JwkStorage>::sign(storage.key_storage(), &key_id, payload, jwk)
          .await
          .map_err(Error::KeyStorageError)?; */
        let kid = method.id().to_string().into_bytes();
        println!("kid in did_sign is : {:?}\n\n", kid);
        //println!("kid length : {}", method.id().to_string().len());
        println!("signature in did sign is: {:?}\n\n", signature);
        let sig = [kid, signature].concat();
        Ok(sig)
      }
    }