// SPDX-License-Identifier: UNLICENSED
// Copyright 2023 Immersve

pragma solidity 0.8.28;

import { ITypes } from "./ITypes.sol";

interface IErrors is ITypes {

  /**
   * @notice Operation needs to be processed in a specific order.
   * Nonce makes sure that the order is correct. Otherwise the
   * nonce is out of sequence and there is a problem with the order
   * of this operation
   */
  error NonceOutOfSequence();

  /**
   * @notice In order to execute this operation, a specific signature
   * is required, and the provided signature is not valid
   */
  error SignatureUnauthorized();

  /**
   * @notice Provided Merkle Root has an invalid value or format
   */
  error MerkleRootInvalid();

  /**
   * @notice Tokens are enabled at the FundsManagerLogic level.
   * Operations trying to use unsupported tokens will fail unless
   * token is manually enabled for support
   */
  error TokenNotSupported(address token);

  /**
   * @notice Operations requires to be ran before the expiry date
   */
  error ExpiryDatePassed();

  /**
   * @notice The sender of the transaction is not authorized
   * to perform this action
   */
  error SenderAccountNotAuthorized(address account);

  /**
   * @notice The provided account address is not an Storage contract
   */
  error StorageAccountInvalid(address source);

  /**
   * @notice The executed operation is not supported by this version
   * of the protocol
   */
  error OperationUnsupported();

  /**
   * @notice Operations are idempotent. If the key is already used it
   * means that the operation was already executed
   */
  error IdempotencyKeyAlreadyUsed();

  /**
   * @notice There is no record of a DirectSpendTransaction for the
   * provided params
   */
  error DirectSpendTransactionNotFound();

  /**
   * @notice Direct Spend is disabled at the FundsManagerLogic level.
   * This feature is disabled by default and must be manually enabled.
   * Direct spend feature should only be enabled for fast EVM chains
   * like ARB or BASE
   */
  error DirectSpendDisabled();

  /**
   * @notice Reversal operation failed because there is not enough
   * liquidity on the storage contract
   */
  error DirectSpendReversalInsufficientFunds();

  /**
   * @notice The Direct Spend Transaction is already expired
   */
  error DirectSpendTransactionExpired();
  /**
   * @notice Operation requires a specific FundingMode. Storage instance
   * funding mode differs from the expected mode for the current operation
   */
  error FundingModeInvalid(FundingMode current, FundingMode expected);
}
