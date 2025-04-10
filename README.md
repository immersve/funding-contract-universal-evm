# Immersve Universal EVM Funding Contract

Solidity smart contract for the Immersve universal-evm card funding protocol.


## Documentation

See https://docs.immersve.com/guides/universal-evm-smart-contract/.


## License

Copyright 2025 Immersve. All rights reserved.


## History


### 1.1.0

**Summary**: Approval based funding enhancements.<br>
**Date**: {pending}<br>
**Audit Report**: {pending}

**Added**
- `directSpendDebit()` _(Master Contract)_
- `directSpendRefund()` _(Master Contract)_
- `directSpendReverse()` _(Master Contract)_
- `directSpendGetTransaction()` _(Master Contract)_
- `enableDirectSpend()` _(Master Contract)_
- `disableDirectSpend()` _(Master Contract)_
- `setDirectSpendReversalCutoffSeconds()` _(Master Contract)_
- `getDirectSpendReversalCutoffSeconds()` _(Master Contract)_
- `addStorageLiquidity()` _(Master Contract)_
- `getFundingMode()` _(Child Contract)_

**Changed**
- `createFundsStorage()` _(Master Contract)_ expects funding mode.
- Required Solidity version 0.8.21 → 0.8.28.
- All proxied functions explicitly fail when not called via proxy.
- Withdrawals and settlements are denied when contract paused.
- Master contract interfaces merged.

**Renamed**
- `getAdminAddress()` _(Master Contract)_ → `getMasterAddress()`
- `getAdminLogicAddress()` _(Master Contract)_ → `getMasterLogicAddress()`

**Removed**
- refund() _(Master Contract)_
- grantRefundTargetManagerRole() _(Master Contract)_
- revokeRefundTargetManagerRole() _(Master Contract)_
- setRefunderAddress() _(Master Contract)_
- getRefunderAddress() _(Master Contract)_
- REFUND_TARGET_MANAGER_ROLE _(Master Contract)_
- REFUND_TARGET_ROLE _(Master Contract)_


### 1.0.0

**Summary**: Universal deposit protocol version 1.0.<br>
**Date**: 2024-01-11<br>
**Audit Report**: [Hashlock Audit Report (PDF)](https://static.immersve.com/public-reports/smart-contracts/funding-contract-universal-evm/202311-hashlock_immersve_v12_22_02_2024.pdf)<br>
