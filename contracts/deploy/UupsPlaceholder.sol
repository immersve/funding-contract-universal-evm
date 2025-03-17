// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { AccessControlUpgradeable } from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";

contract UupsPlaceholder is AccessControlUpgradeable, UUPSUpgradeable {

  /// @custom:oz-upgrades-unsafe-allow constructor
  constructor() {
    _disableInitializers();
  }

  function initialize(address owner) public initializer {
    __AccessControl_init();
    _grantRole(DEFAULT_ADMIN_ROLE, owner);
    __UUPSUpgradeable_init();
  }

  function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {
  }

  function version() external pure returns(uint256) {
    return 0;
  }
}
