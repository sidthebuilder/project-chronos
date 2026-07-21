// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./ChronosVerifier.sol";

/// @title ChronosStaking
/// @notice A staking and slashing marketplace for Chronos Agent compute nodes.
contract ChronosStaking {
    ChronosVerifier public verifier;

    struct Agent {
        uint256 stake;
        bool isActive;
        uint256 pendingTasks;
    }

    mapping(address => Agent) public agents;
    uint256 public constant MINIMUM_STAKE = 1 ether;

    event AgentRegistered(address indexed agent);
    event TaskAssigned(address indexed agent, uint256 taskId);
    event ProofSubmitted(address indexed agent, uint256 taskId, bool success);
    event AgentSlashed(address indexed agent, uint256 amount);

    constructor(address _verifier) {
        verifier = ChronosVerifier(_verifier);
    }

    /// @notice Register as a Chronos Compute Node by staking ETH
    function registerAgent() external payable {
        require(msg.value >= MINIMUM_STAKE, "Insufficient stake");
        agents[msg.sender].stake += msg.value;
        agents[msg.sender].isActive = true;
        emit AgentRegistered(msg.sender);
    }

    /// @notice Assign a task to an agent (in a real system this would hold the encrypted payload)
    function assignTask(address agentAddress, uint256 taskId) external {
        require(agents[agentAddress].isActive, "Agent is not active");
        agents[agentAddress].pendingTasks += 1;
        emit TaskAssigned(agentAddress, taskId);
    }

    /// @notice Submit the ZK-SNARK erasure proof to complete the task
    function submitErasureProof(
        uint256 taskId,
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[1] memory input
    ) external {
        require(agents[msg.sender].isActive, "Agent not active");
        require(agents[msg.sender].pendingTasks > 0, "No pending tasks");

        // Verify the Groth16 zk-SNARK proof on-chain
        bool isValid = verifier.verifyProof(a, b, c, input);

        if (isValid) {
            // Task successful
            agents[msg.sender].pendingTasks -= 1;
            emit ProofSubmitted(msg.sender, taskId, true);
        } else {
            // Cryptographic failure! Slash the agent.
            _slashAgent(msg.sender, agents[msg.sender].stake / 4); // Slash 25% of stake
            emit ProofSubmitted(msg.sender, taskId, false);
        }
    }

    /// @notice Internal slashing mechanic
    function _slashAgent(address agentAddress, uint256 penalty) internal {
        if (agents[agentAddress].stake >= penalty) {
            agents[agentAddress].stake -= penalty;
        } else {
            agents[agentAddress].stake = 0;
            agents[agentAddress].isActive = false;
        }
        emit AgentSlashed(agentAddress, penalty);
    }
}
