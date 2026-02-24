// src/contracts/abis/index.js
// ABI definitions for our smart contracts
// These define the interface between JavaScript and the Solidity contracts

export const DID_REGISTRY_ABI = [
    'function registerDID(string did, address owner, string didDocument) external',
    'function resolveDID(string did) external view returns (string didDocument, address owner, uint256 createdAt, bool active)',
    'function updateDIDDocument(string did, string newDocument) external',
    'function deactivateDID(string did) external',
    'function isDIDActive(string did) external view returns (bool)',
    'event DIDRegistered(string indexed did, address indexed owner, uint256 timestamp)',
    'event DIDUpdated(string indexed did, uint256 timestamp)',
    'event DIDDeactivated(string indexed did, uint256 timestamp)',
]

export const CREDENTIAL_REGISTRY_ABI = [
    'function anchorCredential(bytes32 credentialId, bytes32 credentialHash, string issuerDID, uint256 issuanceTimestamp) external',
    'function getCredentialHash(bytes32 credentialId) external view returns (bytes32)',
    'function getCredentialInfo(bytes32 credentialId) external view returns (bytes32 hash, string issuerDID, uint256 issuanceTimestamp, address anchoredBy)',
    'function addIssuer(address issuer) external',
    'function removeIssuer(address issuer) external',
    'function isAuthorizedIssuer(address issuer) external view returns (bool)',
    'event CredentialAnchored(bytes32 indexed credentialId, bytes32 credentialHash, address indexed anchoredBy)',
    'event IssuerAdded(address indexed issuer)',
    'event IssuerRemoved(address indexed issuer)',
]

export const REVOCATION_ABI = [
    'function revoke(bytes32 credentialId) external',
    'function isRevoked(bytes32 credentialId) external view returns (bool)',
    'function revokeCredential(bytes32 credentialId) external',
    'function getRevocationInfo(bytes32 credentialId) external view returns (bool revoked, uint256 revokedAt, address revokedBy)',
    'event CredentialRevoked(bytes32 indexed credentialId, address indexed revokedBy, uint256 timestamp)',
]
