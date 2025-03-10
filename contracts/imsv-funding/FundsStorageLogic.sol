// SPDX-License-Identifier: UNLICENSED
// Copyright 2023 Immersve

pragma solidity ^0.8.28;

import { IFundsStorage } from "./interfaces/IFundsStorage.sol";
import { IFundsAdmin } from "./interfaces/IFundsAdmin.sol";
import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { EIP712Upgradeable } from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract FundsStorageLogic is IFundsStorage, ReentrancyGuardUpgradeable, EIP712Upgradeable {

  /**
    * The FundsAdmin proxy which provides configurations for any FundsStorage
    * operations.
    */
  IFundsAdmin internal _fundsAdmin;

  /**
    * The user-supplied name of the FundsStorage, useful for aiding with
    * auditing deployed contracts.
    */
  string internal _name;

  /**
    * The token supported by this FundsStorage. Token transfers into this
    * contract which are not from this token are not able to be withdrawn and
    * will be trapped forever.
    */
  IERC20 internal _token;

  /**
    * Mapping of depositor address to withdrawal nonce.
    */
  mapping(address => uint256) internal _usedNonces;

  /**
   * @dev Keep track of already used idempotency keys for debit and refund operations
   */
  mapping(bytes32 => DirectSpendTransaction) internal _directSpendTransactions;

  FundingMode internal _fundingMode;

  /**
    * @dev This initializer will be invoked once for each BeaconProxy created by
    *   the FundsStorageFactory.
    * @param adminAddress The address of the FundsAdmin which supplies
    *   configurations to this FundsStorage.
    * @param token The ERC-20 token to be supported by this funds storage.
    * @param name The name of the funds storage.
    */
  function initialize(address adminAddress, address token, string calldata name, FundingMode fundingMode) public initializer {
    _fundsAdmin = IFundsAdmin(adminAddress);
    _token = IERC20(token);
    _name = name;
    _fundingMode = fundingMode;
    /*
     * Initialize the EIP-712 domain separator used when verifying withdraw signatures.
     */
    __EIP712_init("Immersve.FundsStorageLogic", "1");
  }

  /// @inheritdoc IFundsStorage
  function getName() external view returns(string memory name) {
    return _name;
  }

  /// @inheritdoc IFundsStorage
  function getToken() external view returns(address) {
    return address(_token);
  }

  /// @inheritdoc IFundsStorage
  function getWithdrawalNonce(address depositor) public view returns(uint256) {
    return _usedNonces[depositor];
  }

  /// @inheritdoc IFundsStorage
  function getFundingMode() external view returns(FundingMode) {
    return _fundingMode;
  }

  /// @inheritdoc IFundsStorage
  function withdraw(
      uint256 amount,
      uint256 expiryDate,
      uint256 nonce,
      bytes memory _signature
  ) external nonReentrant {
      _requireFundingMode(FundingMode.DEPOSIT);
      if(block.timestamp > expiryDate) revert ExpiryDatePassed();
      // check if the funds were already withdrawn with this nonce
      if(nonce != _usedNonces[msg.sender] + 1) revert NonceOutOfSequence();
      bytes32 digest = _hashTypedDataV4(
          keccak256(abi.encode(keccak256("WithdrawalIntent(address depositorAddress,uint256 amount,uint256 expiryDate,uint256 nonce)"), msg.sender, amount, expiryDate, nonce))
      );
      _verifySignature(digest, _signature);
      _usedNonces[msg.sender] = nonce;
      if (amount > 0) {
        SafeERC20.safeTransfer(_token, msg.sender, amount);
      }
      emit Withdrawal(msg.sender, amount, expiryDate, nonce, WithdrawalType.ONLINE_SIGNATURE);
  }

  /**
   * @dev Verify that the hash has been signed by an account with WITHDRAWAL_AUTHORIZER role
   **/
  function _verifySignature(bytes32 digest, bytes memory signature) internal view {
      address signer = ECDSA.recover(digest, signature);
      _fundsAdmin._requireWithdrawalSignerAuthorized(signer);
  }

  /// @inheritdoc IFundsStorage
  function transferToSettlementAddress(uint256 amount) external {
    _requireFundsAdmin(msg.sender);
    address settlementAddress = _fundsAdmin.getSettlementAddress(address(_token));
    if(settlementAddress == address(0)) revert TokenNotSupported({ token: address(_token) });
    SafeERC20.safeTransfer(_token, settlementAddress, amount);
  }

  /// @inheritdoc IFundsStorage
  function directSpendDebit(address spender, uint256 amount, bytes32 idempotencyKey) external {
    _requireFundingMode(FundingMode.APPROVAL);
    _requireFundsAdmin(msg.sender);
    _requireUniqueDirectSpendIdempotencyKey(idempotencyKey);
    SafeERC20.safeTransferFrom(_token, spender, address(this), amount);
    _directSpendTransactions[idempotencyKey] = DirectSpendTransaction(
      amount,
      block.timestamp,
      spender,
      DirectSpendOperationType.DEBIT, // operation
      true, // exists?
      0
    );
    emit DirectSpendDebit(spender, amount, idempotencyKey);
  }

  /// @inheritdoc IFundsStorage
  function directSpendGetTransaction(bytes32 idempotencyKey) external view returns(DirectSpendTransaction memory) {
    return _directSpendTransactions[idempotencyKey];
  }

  /// @inheritdoc IFundsStorage
  function directSpendRefund(
    address destinationAddress,
    address sourceAddress,
    uint256 amount,
    bytes32 idempotencyKey
  ) external {
    _requireFundingMode(FundingMode.APPROVAL);
    _requireFundsAdmin(msg.sender);
    _requireUniqueDirectSpendIdempotencyKey(idempotencyKey);
    _directSpendTransactions[idempotencyKey] = DirectSpendTransaction(
      amount,
      block.timestamp,
      destinationAddress,
      DirectSpendOperationType.REFUND, // operation
      true, // exists?
      0
    );
    emit DirectSpendRefund(destinationAddress, sourceAddress, amount, idempotencyKey);
  }

  /// @inheritdoc IFundsStorage
  function directSpendReverse(
    bytes32 originalIdempotencyKey,
    uint256 amount,
    bytes32 idempotencyKey
  ) external {
    _requireFundingMode(FundingMode.APPROVAL);
    _requireFundsAdmin(msg.sender);
    _requireUniqueDirectSpendIdempotencyKey(idempotencyKey);
    DirectSpendTransaction memory directSpendTransaction = _directSpendTransactions[originalIdempotencyKey];
    if(!directSpendTransaction.exists) revert DirectSpendTransactionNotFound();
    if(directSpendTransaction.operationType != DirectSpendOperationType.DEBIT) revert OperationUnsupported();
    _requireUnexpiredDirectSpendTransaction(directSpendTransaction);
    uint256 availableReversalAmount = directSpendTransaction.amount - directSpendTransaction.reversedAmount;
    if(amount > availableReversalAmount) revert DirectSpendReversalInsufficientFunds();
    address destinationAddress = directSpendTransaction.fundingAddress;
    SafeERC20.safeTransfer(_token, destinationAddress, amount);
    _directSpendTransactions[originalIdempotencyKey].reversedAmount = directSpendTransaction.reversedAmount + amount;
    _directSpendTransactions[idempotencyKey] = DirectSpendTransaction(
      amount,
      block.timestamp,
      destinationAddress,
      DirectSpendOperationType.REVERSAL, // operation
      true, // exists?
      amount
    );
    emit DirectSpendReversal(originalIdempotencyKey, destinationAddress, amount, idempotencyKey);
  }

  /// @inheritdoc IFundsStorage
  function addStorageLiquidity(
    address sourceAddress,
    uint256 amount
  ) external {
    _requireFundsAdmin(msg.sender);
    IERC20 token = IERC20(_token);
    SafeERC20.safeTransferFrom(token, sourceAddress, address(this), amount);
  }

  function _requireFundingMode(FundingMode expectedFundingMode) internal view {
    FundingMode currentFundingMode = _fundingMode;
    if(currentFundingMode != expectedFundingMode) revert FundingModeInvalid(currentFundingMode, expectedFundingMode);
  }

  function _requireFundsAdmin(address sender) internal view {
    if(address(_fundsAdmin) != sender) revert SenderAccountNotAuthorized(sender);
  }

  function _requireUniqueDirectSpendIdempotencyKey(bytes32 idempotencyKey) internal view {
    DirectSpendTransaction memory directSpendTransaction = _directSpendTransactions[idempotencyKey];
    if(directSpendTransaction.exists) revert IdempotencyKeyAlreadyUsed();
  }

  function _requireUnexpiredDirectSpendTransaction(DirectSpendTransaction memory transaction) internal {
    uint256 transactionExpiryDate = transaction.timestamp + _fundsAdmin.getDirectSpendReversalCutoffSeconds();
    if(block.timestamp > transactionExpiryDate) revert DirectSpendTransactionExpired();
  }
}
