// SPDX-License-Identifier: UNLICENSED
// Copyright 2023 Immersve

pragma solidity ^0.8.28;

import { IErrors } from "./IErrors.sol";

/**
  * @notice Holder of deposits for an Immersve Funding Channel. Deposits are
  *   made via ERC-20 transfer. Withdrawals are made by getting a signed message
  *   from Immersve Funding Source APIs. To guarantee correct deposit addresses are
  *   used, the Immersve Funding Source APIs can be used to generate the required
  *   deposit transaction parameters.
  *   Approvals are made via ERC-20 approval transactions.
  */
interface IFundsStorage is IErrors {

  /**
    * Type indicator for a withdrawal event.
    */
  enum WithdrawalType{ ONLINE_SIGNATURE, MERKLE_PROOF }

  /**
    * @notice Event logged when a withdrawal is executed.
    * @param depositor The address of the depositor that is withdrawing.
    * @param amount The amount withdrawn.
    * @param expiryDate The withdrawal expiry timestamp.
    * @param nonce The withdrawal nonce.
    * @param withdrawalType The WithdrawalType that was performed.
    */
  event Withdrawal(address depositor, uint256 amount, uint256 expiryDate, uint256 nonce, WithdrawalType withdrawalType);

  /**
   * @notice Event logged when a direct spend debit operation is executed.
   *    This will be called when funding source associated to the funding address
   *    is authorized to spend with an associated Immersve card.
   *
   * @param fundingAddress The address to take funds from
   * @param amount The amount being debited from the funding address
   * @param idempotencyKey A unique key to make operation idempotent
   */
  event DirectSpendDebit(address fundingAddress, uint256 amount, bytes32 idempotencyKey);

  /**
   * @notice Event logged when a direct spend refund operation is executed.
   *    This will be called when a payment is refunded by the card network
   *
   * @param fundingAddress The address to transfer the refund to
   * @param sourceAddress The address of the refund pool
   * @param amount The amount being refunded to the funding address
   * @param idempotencyKey A unique key to make operation idempotent
   */
  event DirectSpendRefund(address fundingAddress, address sourceAddress, uint256 amount, bytes32 idempotencyKey);

  /**
   * @notice Event logged when a direct spend reversal operation is executed.
   *    This will be called when a payment is reversed by the card network
   *
   * @param originalIdempotencyKey The idempotency key of the original direct spend transaction
   * @param fundingAddress The address to transfer the reversal to
   * @param amount The amount being reversed to the funding address
   * @param idempotencyKey A unique key to make operation idempotent
   */
  event DirectSpendReversal(bytes32 originalIdempotencyKey, address fundingAddress, uint256 amount, bytes32 idempotencyKey);

  /**
    * @notice Get the name of the funds storage.
    */
  function getName() external view returns(string memory name);

  /**
    * @notice Get the token supported by the funds storage. The supported token
    *   is defined when the FundsStorage is deployed and cannot change. Token
    *   deposits into a FundsStorage from other tokens cannot be withdrawn and will
    *   be stuck forever.
    */
  function getToken() external view returns(address);

  /**
    * @notice Get the current withdrawal nonce for a depositor. The next
    *   withdrawal transaction must be one more that this value.
    * @param depositor The depositor address.
    */
  function getWithdrawalNonce(address depositor) external view returns(uint256);

  /**
    * @notice Withdraw funds using a signed withdrawal approval. The withdrawal
    *   approval is issued by Immersve Funding Source APIs. The message sender
    *   must be the same address connected to the Immersve Funding Source which
    *   the signed withdrawal approval relates to. A zero-amount withdrawal may
    *   be used to invalidate signed withdrawal approvals without triggering a
    *   token transfer.
    * @param amount The amount being withdrawn.
    * @param expiryDate The timestamp when the signature expires.
    * @param nonce The withdrawal nonce. The withdrawal nonce must be one more
    *   than the the depositor's current withdrawal nonce.
    * @param signature The signed withdrawal appoval.
    */
  function withdraw(
    uint256 amount,
    uint256 expiryDate,
    uint256 nonce,
    bytes memory signature
  ) external;

  /**
    * @notice Perform a settlement transfer. Settlement can only be initiated
    *   by the FundsAdmin contract.
    * @param amount The amount being settled.
    */
  function transferToSettlementAddress(uint256 amount) external;

  /**
   * @notice Perform a debit directly from the spender wallet. Wallet must have
   * granted the approval amount beforehand to the FundsStorage address
   *
   * @param spender The account spending assets with Immersve
   * @param amount The amount being spent by the spender
   * @param idempotencyKey An idempotent key to avoid doing the same operation twice
   */
  function directSpendDebit(address spender, uint256 amount, bytes32 idempotencyKey) external;

  /**
   * @notice Retrieves a direct spend transaction from it's idempotency key
   * @param idempotencyKey The idempotency key of an existing transaction
   */
  function directSpendGetTransaction(bytes32 idempotencyKey) external view returns(DirectSpendTransaction memory);

  /**
   * @notice Storage contract will trigger an erc-20 transfer from the source address into
   * the refundAddress
   *
   * @param destinationAddress The account receiving the refund
   * @param sourceAddress The account providing liquidity for the refund
   * @param amount The amount being refund to the destination address
   * @param idempotencyKey An idempotent key to avoid doing the same operation twice
   */
  function directSpendRefund(
    address destinationAddress,
    address sourceAddress,
    uint256 amount,
    bytes32 idempotencyKey
  ) external;

  /**
   * @notice Executes a payment reversal. Reversals are always linked to
   * existing payments and cannot be higher than the original amount
   *
   * @param originalIdempotencyKey The idempotency key of the original direct spend transaction
   * @param amount The amount being reversed to the destination address
   * @param idempotencyKey An idempotent key to avoid doing the same operation twice
   */
  function directSpendReverse(
    bytes32 originalIdempotencyKey,
    uint256 amount,
    bytes32 idempotencyKey
  ) external;

  /**
   * @notice Executes a transfer from the sourceAddress into the storage address
   * to add liquidity for reversal operations and withdrawals
   *
   * @param sourceAddress The origin of funds to add liquidity from
   * @param amount The amount of funds being added to the storage contract
   */
  function addStorageLiquidity(
    address sourceAddress,
    uint256 amount
  ) external;

  /**
   * @notice Gets the FundingMode configured for the FundsStorage instance
   */
  function getFundingMode() external returns(FundingMode);
}
