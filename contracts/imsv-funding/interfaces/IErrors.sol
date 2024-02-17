// SPDX-License-Identifier: UNLICENSED
// Copyright 2023 Immersve

pragma solidity ^0.8.21;

interface IErrors {

  error NonceOutOfSequence();
  error SignatureUnauthorized();
  error MerkleRootInvalid();
  error TokenNotSupported(address token);

  error ExpiryDatePassed();

  error SettlementNotAuthorizedAccount(address account);
  error SettlementSourceInvalid(address source);
  error RefundTargetNotAuthorized(address target);
  error RefundTargetInvalid(address target);
  error RefunderNotConfigured();

  error OperationUnsupported();
}
