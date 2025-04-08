// SPDX-License-Identifier: UNLICENSED
// Copyright 2023 Immersve

pragma solidity 0.8.28;

import { IErrors } from "./IErrors.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";

/**
  * @notice Administrative management for funds storage.
  */
interface IFundsAdmin is IErrors, IAccessControl {

  /**
    * Role for authorizing withdrawal signatures.
    */
  //solhint-disable-next-line func-name-mixedcase
  function WITHDRAWAL_SIGNER_ROLE() external pure returns(bytes32);

  /**
    * Role for authorizing settlement and refund.
    */
  //solhint-disable-next-line func-name-mixedcase
  function SETTLER_ROLE() external pure returns(bytes32);

  /**
    * @notice Event logged when a settlement is executed.
    * @param from The address of the FundsStorage that is settling.
    * @param amount The amount being settled.
    * @param nonce The settlement nonce.
    */
  event Settlement(address from, uint256 amount, uint256 nonce);

  /**
    * @notice Event logged when a refund is executed.
    * @param refundee The address of the FundsStorage receiving the refund.
    * @param sourceAddress The address of the FundsStorage receiving the refund.
    * @param amount The amount being refunded.
    * @param nonce The settlement nonce.
    */
  event StorageLiquidityAdded(address refundee, address sourceAddress, uint256 amount, uint256 nonce);

  /**
    * @notice Event logged when a new FundsStorage is created.
    * @param token The token used by the FundsStorage.
    * @param addr The address of the created FundsStorage.
    * @param name The name of the created FundsStorage.
    */
  event FundsStorageCreated(address token, address addr, string name);

  /**
    * @notice Get the deployed factory logic version.
    */
  function getVersion() external pure returns(uint256);

  /**
    * @notice Get the deployed factory commit id.
    */
  function getCommitId() external view returns(string memory);

  /**
    * @notice Get the deployed factory build number.
    */
  function getBuildNumber() external view returns(string memory);

  /**
    * @notice Get the address of the beacon used for FundsStorage instances
    * created by this factory.
    */
  function getStorageBeaconAddress() external view returns(address);

  /**
    * @notice Get the address of the FundsAdmin used to configure FundsStorage
  * instances created by this factory.
    */
  function getMasterAddress() external view returns(address);

  /**
   * @notice Create a new FundsStorage. The address of the deployed contract is
   *   determined by the sender address and the name. Deployment will fail if the
   *   a name has already been used from the same message sender.
   * @param token The token supported by the funds storage.
   * @param name The name of the funds storage.
   */
  function createFundsStorage(address token, string calldata name, FundingMode fundingMode) external returns(address);

  /**
    * @notice Check if an address is for a FundsStorage created by this factory.
    * @param addr the address to check.
    */
  function isFundsStorage(address addr) external view returns(bool);

  /**
    * @notice Get the current withdrawal nonce for a FundsStorage. The next
    *   settlement or refund transaction for the FundsStorage must be one more
    *   than this value.
    * @param fundsStorage A FundsStorage address.
    */
  function getSettlementNonce(address fundsStorage) external view returns(uint256);

  /**
    * @notice Settle cleared funds by triggering a token transfer. Only the
    *   settler role can settle.
    * @param from The FundsStorage address to settle from.
    * @param amount The amount to settle.
    * @param nonce The Funds Storage's settlement nonce. The settlement nonce
    *   must be one more than the Funds Storage's current settlement nonce.
    */
  function settle(
    address from,
    uint256 amount,
    uint256 nonce,
    bytes32 merkleRoot
  ) external;

  /**
    * @notice Add storage liquidity to a FundsStorage address. A token tranfer
    *   will be issued from the sourceAddress. Only the settler
    *   role can do this.
    * @param refundee The FundsStorage address to refund to
    * @param sourceAddress The source of funds for the liquidity addition
    * @param amount The liquidity amount to add.
    * @param nonce The settlement nonce. The settlement nonce must be one more than
    *   the Funds Storage's current settlement nonce.
    */
  function addStorageLiquidity(
    address refundee,
    address sourceAddress,
    uint256 amount,
    uint256 nonce,
    bytes32 merkleRoot
  ) external;

  /**
   * @notice Trigger a debit function call to the FundsStorage contract.
   * Storage contract will check for available balance and allowance to try
   * or reject the actual transfer
   *
   * @param storageAddress The Funds Storage address
   * @param spender The account spending assets with Immersve
   * @param amount The amount being spent by the spender
   * @param idempotencyKey An idempotent key to avoid doing the same operation twice
   */
  function directSpendDebit(
    address storageAddress,
    address spender,
    uint256 amount,
    bytes32 idempotencyKey
  ) external;

  /**
   * @notice Trigger a directSpendRefund function call to the FundsStorage contract.
   * Storage contract will trigger an erc-20 transfer from the source address into
   * the destinationAddress
   *
   * @param storageAddress The Funds Storage address
   * @param destinationAddress The account receiving the refund
   * @param sourceAddress The account providing liquidity for the refund
   * @param amount The amount being spent by the spender
   * @param idempotencyKey An idempotent key to avoid doing the same operation twice
   */
  function directSpendRefund(
    address storageAddress,
    address destinationAddress,
    address sourceAddress,
    uint256 amount,
    bytes32 idempotencyKey
  ) external;

  /**
   * @notice Trigger a directSpendReverse function call to the FundsStorage contract.
   * Executes a payment reversal. Reversals are always linked to existing payments
   * and cannot be higher than the original amount
   *
   * @param storageAddress The Funds Storage address
   * @param originalIdempotencyKey The idempotency key of the original direct spend transaction
   * @param amount The amount being reversed to the destination address
   * @param idempotencyKey An idempotent key to avoid doing the same operation twice
   */
  function directSpendReverse(
    address storageAddress,
    bytes32 originalIdempotencyKey,
    uint256 amount,
    bytes32 idempotencyKey
  ) external;

  /**
   * @notice Retrieves a direct spend transaction from a storage
   * contract by it's idempotency key
   *
   * @param storageAddress The Partner FundsStorage contract address
   * @param idempotencyKey The unique idempotency key
   */
  function directSpendGetTransaction(
    address storageAddress,
    bytes32 idempotencyKey
  ) external view returns(DirectSpendTransaction memory);

  /**
    * @notice Update settlement addresses to include the given settlementAddress.
    * @param token The token address to configure.
    * @param settlementAddress The settlement address to allow. Setting settlementAddress
    *    to zero means that the token is not supported anymore.
    */
  function setSettlementAddress(address token, address settlementAddress) external;

  /**
    * @notice Get the settlement address for the specified token.
    * @param token The token for which to get the settlement address.
    */
  function getSettlementAddress(address token) external view returns(address);

  /**
    * @notice Transfer the DEFAULT_ADMIN_ROLE to a new account/
    * @param adminAccount The new account that can invoke all admin functions.
    */
  function transferDefaultAdminRole(address adminAccount) external;
  /**
    * @notice Grant the WITHDRAWAL_SIGNER_ROLE.
    * @param withdrawalSigner The address that can authorize withdrawals.
    */
  function grantWithdrawalSignerRole(address withdrawalSigner) external;

  /**
    * @notice Revoke the WITHDRAWAL_SIGNER_ROLE.
    * @param withdrawalSigner The address that can authorize withdrawals.
    */
  function revokeWithdrawalSignerRole(address withdrawalSigner) external;

  /**
    * @notice Grant the SETTLER_ROLE.
    * @param settlerAddress The address that can perform settle and refund.
    */
  function grantSettlerRole(address settlerAddress) external;

  /**
    * @notice Revoke the SETTLER_ROLE.
    * @param settlerAddress The address that can perform settle and refund.
    */
  function revokeSettlerRole(address settlerAddress) external;

  /**
    * @notice Check if the provided address is authorized to do withdrawals
    * @param signerAuthorizer The address to verify.
    */
  // solhint-disable-next-line private-vars-leading-underscore
  function _requireWithdrawalSignerAuthorized(address signerAuthorizer) external view;

  /**
   * @notice Requires master contract to be unpaused. Otherwise, an error is thrown
   */
  // solhint-disable-next-line private-vars-leading-underscore
  function _requireMasterNotPaused() external view;
  /**
   * @notice Pause all token transfer operations
   */
  function pause() external;

  /**
   * @notice Resume all token transfer operations
   */
  function unpause() external;

  /**
   * @notice Enables direct spend funding mode
   */
  function enableDirectSpend() external;

  /**
   * @notice Disable direct spend funding mode
   */
  function disableDirectSpend() external;

  function setDirectSpendReversalCutoffSeconds(uint256 expiry) external;

  function getDirectSpendReversalCutoffSeconds() external returns(uint256);
}
