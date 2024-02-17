// SPDX-License-Identifier: UNLICENSED
// Copyright 2023 Immersve

pragma solidity ^0.8.21;

import { IErrors } from "./IErrors.sol";

/**
  * @notice Holder of deposits for an Immersve Funding Channel. Deposits are
  *   made via ERC-20 transfer. Withdrawals are made by getting a signed message
  *   from Immersve Funding Source APIs. To guarantee correct deposit addresses are
  *   used, the Immersve Funding Source APIs can be used to generate the required
  *   deposit transaction parameters.
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
}
