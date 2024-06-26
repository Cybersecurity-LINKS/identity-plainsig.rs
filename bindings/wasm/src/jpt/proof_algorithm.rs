// Copyright 2020-2024 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use jsonprooftoken::jpa::algs::ProofAlgorithm;
use wasm_bindgen::prelude::*;

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[wasm_bindgen(js_name = ProofAlgorithm)]
pub enum WasmProofAlgorithm {
  BLS12381_SHA256,
  BLS12381_SHAKE256,
  SU_ES256,
  MAC_H256,
  MAC_H384,
  MAC_H512,
  MAC_K25519,
  MAC_K448,
  MAC_H256K,
}

impl From<ProofAlgorithm> for WasmProofAlgorithm {
  fn from(value: ProofAlgorithm) -> Self {
    match value {
      ProofAlgorithm::BLS12381_SHA256 => WasmProofAlgorithm::BLS12381_SHA256,
      ProofAlgorithm::BLS12381_SHAKE256 => WasmProofAlgorithm::BLS12381_SHAKE256,
      ProofAlgorithm::SU_ES256 => WasmProofAlgorithm::SU_ES256,
      ProofAlgorithm::MAC_H256 => WasmProofAlgorithm::MAC_H256,
      ProofAlgorithm::MAC_H384 => WasmProofAlgorithm::MAC_H384,
      ProofAlgorithm::MAC_H512 => WasmProofAlgorithm::MAC_H512,
      ProofAlgorithm::MAC_K25519 => WasmProofAlgorithm::MAC_K25519,
      ProofAlgorithm::MAC_K448 => WasmProofAlgorithm::MAC_K448,
      ProofAlgorithm::MAC_H256K => WasmProofAlgorithm::MAC_H256K,
    }
  }
}

impl From<WasmProofAlgorithm> for ProofAlgorithm {
  fn from(value: WasmProofAlgorithm) -> Self {
    match value {
      WasmProofAlgorithm::BLS12381_SHA256 => ProofAlgorithm::BLS12381_SHA256,
      WasmProofAlgorithm::BLS12381_SHAKE256 => ProofAlgorithm::BLS12381_SHAKE256,
      WasmProofAlgorithm::SU_ES256 => ProofAlgorithm::SU_ES256,
      WasmProofAlgorithm::MAC_H256 => ProofAlgorithm::MAC_H256,
      WasmProofAlgorithm::MAC_H384 => ProofAlgorithm::MAC_H384,
      WasmProofAlgorithm::MAC_H512 => ProofAlgorithm::MAC_H512,
      WasmProofAlgorithm::MAC_K25519 => ProofAlgorithm::MAC_K25519,
      WasmProofAlgorithm::MAC_K448 => ProofAlgorithm::MAC_K448,
      WasmProofAlgorithm::MAC_H256K => ProofAlgorithm::MAC_H256K,
    }
  }
}
