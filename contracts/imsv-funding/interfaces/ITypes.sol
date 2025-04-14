// SPDX-License-Identifier: UNLICENSED
// Copyright 2025 Immersve

pragma solidity ^0.8.28;


/**
 * @notice Interface containing common direct spend types
 */
interface ITypes {

  /**
   * @notice Direct Spend operation
   * - DEBIT: Transfer assets from funding address into storage contract
   * - REFUND: Transfer assets from refund pool into funding address
   * - REVERSAL: Transfer assets from storage contract into funding address
   */
  enum DirectSpendOperationType{ DEBIT, REFUND, REVERSAL }

  /**
   * @notice Funding Mode
   * - DEPOSIT: Funding address is required to do a deposit on the storage
   * contract via ERC-20 transfer. Balance, debits and refunds are kept
   * fully off-chain.
   * - APPROVAL: Funding address is required to approve ERC-20 approval to
   * the storage contract. Debits are executed during payments and refunds
   * are executed when funds become available in the refund pool
   *
   * See: https://docs.immersve.com/guides/funding-protocols/#protocol-variants
   */
  enum FundingMode{ DEPOSIT, APPROVAL }

  /** @dev The details of a Direct Spend transaction */
  struct DirectSpendTransaction {
    uint256 amount;
    uint256 timestamp; // epoch
    address fundingAddress;
    DirectSpendOperationType operationType;
    bool exists;
    uint256 reversedAmount;
  }
}
