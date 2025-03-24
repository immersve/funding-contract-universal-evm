// SPDX-License-Identifier: UNLICENSED
// Copyright 2023 Immersve

pragma solidity 0.8.28;

import { ITypes } from "./ITypes.sol";

/**
 * @notice Factory for creating FundsStorage instances.
 */
interface IFundsStorageFactory is ITypes {

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
  function getAdminAddress() external view returns(address);

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

}
