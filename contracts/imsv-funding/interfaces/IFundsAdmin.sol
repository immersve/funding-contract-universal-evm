// SPDX-License-Identifier: UNLICENSED
// Copyright 2023 Immersve

pragma solidity ^0.8.21;

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
   * Role for managing refund targets
   */
  //solhint-disable-next-line func-name-mixedcase
  function REFUND_TARGET_MANAGER_ROLE() external pure returns(bytes32);

  /**
   * Role given to refund targets (FundsStorage instances) to validate that they authorized for refunds
   *   After a FundsStorage address is registered as an Immersve Funding Channel
   *   it can be used to create Funding Sources for funding cards. However, the FundsStorage will
   *   not be allowed to receive refunds until it is also registered as a
   *   refundee here.
   */
  //solhint-disable-next-line func-name-mixedcase
  function REFUND_TARGET_ROLE() external pure returns(bytes32);

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
    * @param amount The amount being refunded.
    * @param nonce The settlement nonce.
    */
  event Refund(address refundee, uint256 amount, uint256 nonce);

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
    * @notice Trigger a refund back to a FundsStorage address. A token tranfer
    *   will be issued from the refunderAddress. Only the settler
    *   role can refund.
    * @param refundee The FundsStorage address to refund to. Refunds will only
    *   be allowed to addresses that have been whitelisted as a refund address.
    * @param amount The amount to refund.
    * @param nonce The refund nonce. The refund nonce must be one more than the
    *   Funds Storage's current settlement nonce.
    */
  function refund(
    address refundee,
    uint256 amount,
    uint256 nonce,
    bytes32 merkleRoot
  ) external;

  /**
    * @notice Update settlement addresses to include the given settlementAddress.
    * @param token The token address to configure.
    * @param settlementAddress The settlement address to allow. Setting settlementAddress
    *    to zero means that the token is not supported anymore.
    */
  function setSettlementAddress(address token, address settlementAddress) external;

  /**
   * @notice Verifies that the token is supported by the admin contract.
   *  To be able to support a token, it's settlement address needs to be set
   *  by {setSettlementAddress}
   * @param token The ERC-20 token to verify
   */
  function requireTokenSupported(address token) external view;

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
   * @notice Grant the REFUND_TARGET_MANAGER_ROLE.
   * @param managerAddress The address that is allowed to configure refund targets
   */
  function grantRefundTargetManagerRole(address managerAddress) external;

  /**
    * @notice Revoke the REFUND_TARGET_MANAGER_ROLE.
    * @param managerAddress The address that is allowed to configure refund targets
    */
  function revokeRefundTargetManagerRole(address managerAddress) external;

  /**
    * @notice Check if the provided address is authorized to do withdrawals
    * @param signerAuthorizer The address to verify.
    */
  function requireWithdrawalSignerAuthorized(address signerAuthorizer) external view;

  /**
    * @notice Update the refunder address. The refunder address is the source
    *   for refunding ERC-20 transfers.
    * @param refunderAddress The refunder address that approves this contract to
    *   perform token transfers for refunds.
    */
  function setRefunderAddress(address refunderAddress) external;

  /**
   * @notice Get the refunder address. The refunder address is the source
   *   for refunding ERC-20 transfers.
   */
  function getRefunderAddress() external view returns(address);

  /**
    * @notice Grant the REFUND_TARGET_MANAGER_ROLE.
    * @param refundTarget The FundsStorage for which to allow refunds.
    */
  function grantRefundTargetRole(address refundTarget) external;

  /**
    * @notice Revoke the REFUND_TARGET_MANAGER_ROLE.
    * @param refundTarget The FundsStorage for which to allow refunds.
    */
  function revokeRefundTargetRole(address refundTarget) external;

  /**
   * @notice Pause all token transfer operations
   */
  function pause() external;

  /**
   * @notice Resume all token transfer operations
   */
  function unpause() external;
}
