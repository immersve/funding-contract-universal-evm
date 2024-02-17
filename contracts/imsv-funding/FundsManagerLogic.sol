// SPDX-License-Identifier: UNLICENSED
// Copyright 2023 Immersve

pragma solidity ^0.8.21;

import { IFundsStorageFactory } from "./interfaces/IFundsStorageFactory.sol";
import { IFundsAdmin } from "./interfaces/IFundsAdmin.sol";
import { IFundsStorage } from "./interfaces/IFundsStorage.sol";
import { FundsStorageLogic } from "./FundsStorageLogic.sol";
import { BeaconProxy } from "@openzeppelin/contracts/proxy/beacon/BeaconProxy.sol";
import { UpgradeableBeacon } from "@openzeppelin/contracts/proxy/beacon/UpgradeableBeacon.sol";
import { ERC1967Utils } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { AccessControlUpgradeable } from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import { IAccessControl } from "@openzeppelin/contracts/access/IAccessControl.sol";
import { PausableUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import { SafeERC20 } from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract FundsManagerLogic is AccessControlUpgradeable, UUPSUpgradeable, PausableUpgradeable, IFundsStorageFactory, IFundsAdmin {

  /**
   * The FundsStorageLogic beacon.
   */
  UpgradeableBeacon internal _fundsStorageBeacon;

  /**
   * The FundsStorageLogic implementation contract.
   * This storage slot will NOT be initialized on a proxy.
   */
  address internal _storageLogicAddress;

  /**
   * The FundsAdminLogic implementation contract.
   * This storage slot will NOT be initialized on a proxy.
   */
  address internal _adminLogicAddress;

  /**
    * A build number supplied when (re)initializing.
    */
  string internal _buildNumber;

  /**
    * A VCS commit id supplied when (re)initializing.
    */
  string internal _commitId;

  struct FundStorageConfig {
    bool isInstance;
  }

  /**
   * Addresses of FundsStorage beacon proxies that have been created by this factory.
   */
  mapping (address => FundStorageConfig) internal _fundsStorageInstances;

  /// @inheritdoc IFundsAdmin
  bytes32 public constant WITHDRAWAL_SIGNER_ROLE = keccak256("WITHDRAWAL_AUTHORIZER_ROLE");

  /// @inheritdoc IFundsAdmin
  bytes32 public constant SETTLER_ROLE = keccak256("SETTLER_ROLE");

  /// @inheritdoc IFundsAdmin
  bytes32 public constant REFUND_TARGET_MANAGER_ROLE = keccak256("REFUND_TARGET_MANAGER_ROLE");

  /// @inheritdoc IFundsAdmin
  bytes32 public constant REFUND_TARGET_ROLE = keccak256("REFUND_TARGET_ROLE");

  /**
    * Mapping of token address to funds settlement address. The settlement
    * address is the only address to which funds storage instance token deposits
    * can be transfered as part of the settlement process. When a settlement
    * address is not set (ie. `address(0)`) then the token is NOT supported.
    */
  mapping(address => address) internal _tokenSettlementAddress;

  /**
    * Mapping of funds storage address to settlement nonce.
    */
  mapping(address => uint256) internal _fundsStorageSettlementNonce;

  /**
   * The address to withdraw refunds from
   */
  address internal _refunderAddress;

  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor() {
    // invoked in the context of the contract being deployed
    _disableInitializers();
    _storageLogicAddress = address(new FundsStorageLogic());
    _adminLogicAddress = address(this);
  }

  /**
   * @dev This initializer will be run after every upgrade.
   * @param commitId A reference to the VCS commit that this contract is initialized from.
   * @param buildNumber A reference to the build number for this contract initialization.
   */
  function initialize(string calldata commitId, string calldata buildNumber) public onlyProxy onlyRole(DEFAULT_ADMIN_ROLE) {
    /*
     * Warning: this initializer must guard against reinitialization!
     *
     * The initializer acts like a constructor for initializing state on a
     * delegating proxy. Normally the "initializer" modifier is used to prevent
     * it being invoked multiple times. We have removed the guard in order to
     * simplify our contract upgrade process; we always call "initialize" when
     * performing a proxy upgrade.
     *
     * It is the duty of this initializer to do nothing when the proxy state is
     * already initialized.
     */
    bool _proxiesInitialized = address(_fundsStorageBeacon) != address(0);
    if(!_proxiesInitialized) {
      _initialize();
    }
    _buildNumber = buildNumber;
    _commitId = commitId;
  }

  function _initialize() internal reinitializer(2) onlyProxy {
    address implAddress = ERC1967Utils.getImplementation();
    FundsManagerLogic impl = FundsManagerLogic(implAddress);
    _fundsStorageBeacon = new UpgradeableBeacon(impl.getStorageLogicAddress(), address(this));
    PausableUpgradeable.__Pausable_init();
  }

  /// @inheritdoc IFundsStorageFactory
  function getStorageBeaconAddress() public view returns(address) {
    return address(_fundsStorageBeacon);
  }

  function getStorageLogicAddress() public view returns(address) {
    return _storageLogicAddress;
  }

  /// @inheritdoc IFundsStorageFactory
  function getAdminAddress() public view returns(address) {
    return address(this);
  }

  function getAdminLogicAddress() public view returns(address) {
    return _adminLogicAddress;
  }

  function _authorizeUpgrade(address newImplementation) internal view override onlyRole(DEFAULT_ADMIN_ROLE) {
  }

  /// @inheritdoc UUPSUpgradeable
  function upgradeToAndCall(address newImplAddress, bytes memory data) public payable override onlyProxy {
    super.upgradeToAndCall(newImplAddress, data);
    FundsManagerLogic newImpl = FundsManagerLogic(newImplAddress);
    _fundsStorageBeacon.upgradeTo(newImpl.getStorageLogicAddress());
  }

  /// @inheritdoc IFundsStorageFactory
  function getVersion() external pure returns(uint256) {
    return 1;
  }

  /// @inheritdoc IFundsStorageFactory
  function getCommitId() external view returns(string memory) {
    return _commitId;
  }

  /// @inheritdoc IFundsStorageFactory
  function getBuildNumber() external view returns(string memory) {
    return _buildNumber;
  }

  /// @inheritdoc IFundsStorageFactory
  function createFundsStorage(address token, string calldata name) external onlyProxy returns(address) {
    requireTokenSupported(token);
    /*
     * Salt for create2 will be sender address padded with first 96 bits of hash(name)
     * Bitmask is equal to: ethers.toBeHex(((1n << 96n) - 1n) << 160n)
     */
    uint256 bitmask = 0xffffffffffffffffffffffff0000000000000000000000000000000000000000;
    uint256 nameHash = uint256(keccak256(bytes(name)));
    uint256 salt = (nameHash & bitmask) + uint160(msg.sender);
    /*
     * Beacon proxy is created without providing encoded initializer data,
     * making constructor bytes always the same. This simplifies counterfactual address
     * calculation.
     */
    BeaconProxy proxy = new BeaconProxy{ salt: bytes32(salt) }( address(_fundsStorageBeacon), new bytes(0));
    FundsStorageLogic(address(proxy)).initialize(address(this), token, name);
    _fundsStorageInstances[address(proxy)].isInstance = true;
    emit FundsStorageCreated(token, address(proxy), name);
    return address(proxy);
  }

  /// @inheritdoc IFundsStorageFactory
  function isFundsStorage(address addr) public view returns(bool) {
    return _fundsStorageInstances[addr].isInstance;
  }

  /// @inheritdoc IFundsAdmin
  function getSettlementNonce(address fundsStorage) public view returns(uint256) {
    return _fundsStorageSettlementNonce[fundsStorage];
  }

  /// @inheritdoc IFundsAdmin
  function settle(
    address from,
    uint256 amount,
    uint256 nonce,
    bytes32 merkleRoot
  ) external onlyRole(SETTLER_ROLE) whenNotPaused {
    /*
     * The bytes32(0) is required for forwards compatibility. In future, when
     * merkle withdraw is implemented, the bytes32(0) merkle root will be
     * disallowed.
     */
    if(merkleRoot != bytes32(0)) revert MerkleRootInvalid();
    if(!isFundsStorage(from)) revert SettlementSourceInvalid(from);
    if(nonce != _fundsStorageSettlementNonce[from] + 1) revert NonceOutOfSequence();
    IFundsStorage fundsStorage = IFundsStorage(from);
    fundsStorage.transferToSettlementAddress(amount);
    _fundsStorageSettlementNonce[from] = nonce;
    emit Settlement(from, amount, nonce);
  }

  /// @inheritdoc IFundsAdmin
  function refund(
    address refundee,
    uint256 amount,
    uint256 nonce,
    bytes32 merkleRoot
  ) external onlyRole(SETTLER_ROLE) whenNotPaused {
    // We are checking that the refundee has a REFUND_TARGET_ROLE because this role is granted
    // after registering a Funding Channel with Immersve Backend. Once onboarded, Immersve will
    // grant the refundee (an instance of a FundsStorage contract) the role of REFUND_TARGET
    // so it can start receiving funds in the case of refunds. The granting of this role makes sure
    // that the refundee was created by the FundsManager using the isFundsStorage function
    if(merkleRoot != bytes32(0)) revert MerkleRootInvalid();
    if(!hasRole(REFUND_TARGET_ROLE, refundee)) revert RefundTargetNotAuthorized({ target: refundee });
    if(nonce != _fundsStorageSettlementNonce[refundee] + 1) revert NonceOutOfSequence();
    if(_refunderAddress == address(0)) revert RefunderNotConfigured();
    IFundsStorage fundsStorage = IFundsStorage(refundee);
    address tokenAddress = fundsStorage.getToken();
    requireTokenSupported(tokenAddress);
    IERC20 token = IERC20(tokenAddress);
    SafeERC20.safeTransferFrom(token, _refunderAddress, refundee, amount);
    _fundsStorageSettlementNonce[refundee] = nonce;
    emit Refund(refundee, amount, nonce);
  }

  /// @inheritdoc IFundsAdmin
  function requireTokenSupported(address token) public view {
    if (_tokenSettlementAddress[token] == address(0)) revert TokenNotSupported({ token: token });
  }

  /// @inheritdoc IFundsAdmin
  function setSettlementAddress(address token, address settlementAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
    _tokenSettlementAddress[token] = settlementAddress;
  }

  /// @inheritdoc IFundsAdmin
  function getSettlementAddress(address token) external view returns(address) {
    return _tokenSettlementAddress[token];
  }

  /// @inheritdoc IFundsAdmin
  function transferDefaultAdminRole(address adminAccount) external onlyRole(DEFAULT_ADMIN_ROLE) {
    _grantRole(DEFAULT_ADMIN_ROLE, adminAccount);
    _revokeRole(DEFAULT_ADMIN_ROLE, msg.sender);
  }

  /**
   * @dev Prevents direct role assignment. Use specific grant functions instead
   */
  function grantRole(bytes32 /*role*/, address /*account*/) public pure override(AccessControlUpgradeable, IAccessControl) {
    revert OperationUnsupported();
  }

  /**
   * @dev Prevents direct role revocation. Use specific revoke functions instead
   */
  function revokeRole(bytes32 /*role*/, address /*account*/) public pure override(AccessControlUpgradeable, IAccessControl) {
    revert OperationUnsupported();
  }

  /// @inheritdoc IFundsAdmin
  function grantWithdrawalSignerRole(address withdrawalSigner) external onlyRole(DEFAULT_ADMIN_ROLE) {
    _grantRole(WITHDRAWAL_SIGNER_ROLE, withdrawalSigner);
  }

  /// @inheritdoc IFundsAdmin
  function revokeWithdrawalSignerRole(address withdrawalSigner) external onlyRole(DEFAULT_ADMIN_ROLE) {
    _revokeRole(WITHDRAWAL_SIGNER_ROLE, withdrawalSigner);
  }

  /// @inheritdoc IFundsAdmin
  function grantSettlerRole(address settlerAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
    _grantRole(SETTLER_ROLE, settlerAddress);
  }

  /// @inheritdoc IFundsAdmin
  function revokeSettlerRole(address settlerAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
    _revokeRole(SETTLER_ROLE, settlerAddress);
  }

  /// @inheritdoc IFundsAdmin
  function grantRefundTargetManagerRole(address managerAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
    _grantRole(REFUND_TARGET_MANAGER_ROLE, managerAddress);
  }

  /// @inheritdoc IFundsAdmin
  function revokeRefundTargetManagerRole(address managerAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
    _revokeRole(REFUND_TARGET_MANAGER_ROLE, managerAddress);
  }

  /// @inheritdoc IFundsAdmin
  function requireWithdrawalSignerAuthorized(address signerAuthorizer) external view  whenNotPaused {
    if (!hasRole(WITHDRAWAL_SIGNER_ROLE, signerAuthorizer)) revert SignatureUnauthorized();
  }

  /// @inheritdoc IFundsAdmin
  function setRefunderAddress(address refunderAddress) external onlyRole(DEFAULT_ADMIN_ROLE) {
    _refunderAddress = refunderAddress;
  }

  /// @inheritdoc IFundsAdmin
  function getRefunderAddress() external view returns(address) {
    return _refunderAddress;
  }

  /// @inheritdoc IFundsAdmin
  function grantRefundTargetRole(address refundTarget) external onlyRole(REFUND_TARGET_MANAGER_ROLE) {
    if(!isFundsStorage(refundTarget)) revert RefundTargetInvalid({ target: refundTarget });
    _grantRole(REFUND_TARGET_ROLE, refundTarget);
  }

  /// @inheritdoc IFundsAdmin
  function revokeRefundTargetRole(address refundee) external onlyRole(REFUND_TARGET_MANAGER_ROLE) {
    _revokeRole(REFUND_TARGET_ROLE, refundee);
  }

  /// @inheritdoc IFundsAdmin
  function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
    _pause();
  }

  /// @inheritdoc IFundsAdmin
  function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
    _unpause();
  }
}
