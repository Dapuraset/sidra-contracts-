// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title SecurityAudit_v2.1_Enhanced
 * @author SidraChain
 * @notice Advanced on-chain audit registry with secure verification, reward control, and ECDSA validation.
 *
 * Features:
 * - Role-based access control (Admin, Auditor)
 * - On-chain audit registry with cryptographic proof
 * - Optional owner verification via external OwnerRegistry
 * - Optional ERC20 reward mechanism for auditors
 * - ECDSA off-chain signed audit report verification
 * - Reentrancy-safe reward distribution
 * - Emergency pause and configurable registry parameters
 */

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IOwnerRegistry {
    function ownerOf(address contractAddress) external view returns (address);
}

contract SecurityAudit_v2_1_Enhanced is AccessControl, ReentrancyGuard, Pausable {
    using ECDSA for bytes32;

    bytes32 public constant ADMIN_ROLE = DEFAULT_ADMIN_ROLE;
    bytes32 public constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");

    IOwnerRegistry public ownerRegistry;
    IERC20 public rewardToken;
    uint256 public rewardAmount;

    enum AuditStatus { Unknown, Passed, Failed, ManualReview }

    struct AuditRecord {
        address contractAudited;
        address auditor;
        AuditStatus status;
        string reportHash; // IPFS CID or SHA256
        uint256 timestamp;
        string metadata;
    }

    mapping(bytes32 => AuditRecord) private _auditRecords;
    mapping(bytes32 => bool) public auditExists;

    event AuditLogged(bytes32 indexed auditId, address indexed contractAudited, address indexed auditor, AuditStatus status, uint256 timestamp);
    event RewardIssued(address indexed auditor, uint256 amount);
    event OwnerRegistryUpdated(address previous, address current);
    event RewardTokenUpdated(address previous, address current);
    event RewardAmountUpdated(uint256 previous, uint256 current);

    constructor(address _ownerRegistry, address _rewardToken, uint256 _rewardAmount) {
        _setupRole(ADMIN_ROLE, msg.sender);
        _setupRole(AUDITOR_ROLE, msg.sender);

        ownerRegistry = IOwnerRegistry(_ownerRegistry);
        rewardToken = IERC20(_rewardToken);
        rewardAmount = _rewardAmount;
    }

    // ------------------------- MODIFIERS -------------------------
    modifier onlyAdmin() {
        require(hasRole(ADMIN_ROLE, msg.sender), "SecurityAudit: caller is not admin");
        _;
    }

    modifier onlyAuditor() {
        require(hasRole(AUDITOR_ROLE, msg.sender), "SecurityAudit: caller is not auditor");
        _;
    }

    // ------------------------- ADMIN FUNCTIONS -------------------------
    function setOwnerRegistry(address _ownerRegistry) external onlyAdmin {
        emit OwnerRegistryUpdated(address(ownerRegistry), _ownerRegistry);
        ownerRegistry = IOwnerRegistry(_ownerRegistry);
    }

    function setRewardToken(address _rewardToken) external onlyAdmin {
        emit RewardTokenUpdated(address(rewardToken), _rewardToken);
        rewardToken = IERC20(_rewardToken);
    }

    function setRewardAmount(uint256 _rewardAmount) external onlyAdmin {
        emit RewardAmountUpdated(rewardAmount, _rewardAmount);
        rewardAmount = _rewardAmount;
    }

    function pause() external onlyAdmin {
        _pause();
    }

    function unpause() external onlyAdmin {
        _unpause();
    }

    // ------------------------- CORE AUDIT FUNCTIONS -------------------------
    function logAudit(
        address _contractAudited,
        AuditStatus _status,
        string memory _reportHash,
        string memory _metadata
    ) external onlyAuditor whenNotPaused nonReentrant returns (bytes32) {
        require(_contractAudited != address(0), "Invalid audited contract");
        require(bytes(_reportHash).length > 0, "Missing report hash");

        // Verify ownership if registry set
        if (address(ownerRegistry) != address(0)) {
            address owner = ownerRegistry.ownerOf(_contractAudited);
            require(owner != address(0), "Unregistered contract owner");
        }

        bytes32 auditId = keccak256(abi.encodePacked(_contractAudited, msg.sender, _reportHash, block.timestamp));
        require(!auditExists[auditId], "Audit already exists");

        _auditRecords[auditId] = AuditRecord({
            contractAudited: _contractAudited,
            auditor: msg.sender,
            status: _status,
            reportHash: _reportHash,
            timestamp: block.timestamp,
            metadata: _metadata
        });
        auditExists[auditId] = true;

        emit AuditLogged(auditId, _contractAudited, msg.sender, _status, block.timestamp);

        if (address(rewardToken) != address(0) && rewardAmount > 0) {
            rewardToken.transfer(msg.sender, rewardAmount);
            emit RewardIssued(msg.sender, rewardAmount);
        }

        return auditId;
    }

    // ------------------------- ECDSA SIGNED AUDIT -------------------------
    function verifySignedAudit(
        address _contractAudited,
        AuditStatus _status,
        string memory _reportHash,
        string memory _metadata,
        bytes memory signature
    ) external onlyAuditor whenNotPaused nonReentrant returns (bytes32) {
        bytes32 msgHash = keccak256(abi.encodePacked(_contractAudited, _status, _reportHash, _metadata)).toEthSignedMessageHash();
        address recovered = msgHash.recover(signature);
        require(hasRole(AUDITOR_ROLE, recovered), "Invalid auditor signature");

        bytes32 auditId = keccak256(abi.encodePacked(_contractAudited, recovered, _reportHash, block.timestamp));
        require(!auditExists[auditId], "Signed audit exists");

        _auditRecords[auditId] = AuditRecord({
            contractAudited: _contractAudited,
            auditor: recovered,
            status: _status,
            reportHash: _reportHash,
            timestamp: block.timestamp,
            metadata: _metadata
        });
        auditExists[auditId] = true;

        emit AuditLogged(auditId, _contractAudited, recovered, _status, block.timestamp);

        if (address(rewardToken) != address(0) && rewardAmount > 0) {
            rewardToken.transfer(recovered, rewardAmount);
            emit RewardIssued(recovered, rewardAmount);
        }

        return auditId;
    }

    // ------------------------- VIEW FUNCTIONS -------------------------
    function getAuditRecord(bytes32 auditId) external view returns (AuditRecord memory) {
        require(auditExists[auditId], "Audit does not exist");
        return _auditRecords[auditId];
    }

    function getAuditStatus(bytes32 auditId) external view returns (AuditStatus) {
        require(auditExists[auditId], "Audit not found");
        return _auditRecords[auditId].status;
    }
}
