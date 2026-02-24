// src/services/blockchain.service.js
// The ONLY place in the backend that talks directly to smart contracts.
// If you ever change contract addresses or switch networks, you only update here.

import { ethers } from 'ethers'
import {
    DID_REGISTRY_ABI,
    CREDENTIAL_REGISTRY_ABI,
    REVOCATION_ABI,
} from '../contracts/abis/index.js'
import addresses from '../contracts/addresses.js'
import blockchainConfig from '../config/blockchain.config.js'

class BlockchainService {
    constructor() {
        this.provider = null
        this.issuerWallet = null
        this.didRegistry = null
        this.credentialRegistry = null
        this.revocationRegistry = null
        this._initialized = false
    }

    /**
     * Lazy initialization — we don't connect to the blockchain at import time.
     * This avoids crashes when running unit tests or when the RPC is temporarily down.
     */
    _ensureInitialized() {
        if (this._initialized) return

        const rpcUrl = blockchainConfig.network.rpcUrl
        if (!rpcUrl) {
            throw new Error('POLYGON_RPC_URL is not set in environment')
        }

        this.provider = new ethers.JsonRpcProvider(rpcUrl)

        // Issuer wallet — loaded from env, never hardcoded
        const privateKey = blockchainConfig.issuer.privateKey
        if (privateKey && privateKey !== 'REDACTED') {
            this.issuerWallet = new ethers.Wallet(privateKey, this.provider)
        } else {
            // In dev mode, create a random wallet so the service doesn't crash
            console.warn('⚠️  Using placeholder issuer key — set ISSUER_PRIVATE_KEY for production')
            this.issuerWallet = ethers.Wallet.createRandom().connect(this.provider)
        }

        // Instantiate contracts (will only work when real addresses are deployed)
        if (addresses.DID_REGISTRY && addresses.DID_REGISTRY !== '0x0000000000000000000000000000000000000000') {
            this.didRegistry = new ethers.Contract(
                addresses.DID_REGISTRY,
                DID_REGISTRY_ABI,
                this.issuerWallet
            )
        }

        if (addresses.CREDENTIAL_REGISTRY && addresses.CREDENTIAL_REGISTRY !== '0x0000000000000000000000000000000000000000') {
            this.credentialRegistry = new ethers.Contract(
                addresses.CREDENTIAL_REGISTRY,
                CREDENTIAL_REGISTRY_ABI,
                this.issuerWallet
            )
        }

        if (addresses.REVOCATION_REGISTRY && addresses.REVOCATION_REGISTRY !== '0x0000000000000000000000000000000000000000') {
            this.revocationRegistry = new ethers.Contract(
                addresses.REVOCATION_REGISTRY,
                REVOCATION_ABI,
                this.issuerWallet
            )
        }

        this._initialized = true
    }

    // ─── DID Operations ──────────────────────────────────────────────

    /**
     * Register a DID on-chain with its DID document.
     */
    async registerDID(did, ownerAddress, didDocument) {
        this._ensureInitialized()
        if (!this.didRegistry) {
            console.warn('⚠️  DID Registry not deployed — skipping on-chain registration')
            return { txHash: null, blockNumber: null, simulated: true }
        }

        try {
            const tx = await this.didRegistry.registerDID(
                did,
                ownerAddress,
                JSON.stringify(didDocument)
            )
            const receipt = await tx.wait()
            return {
                txHash: receipt.hash,
                blockNumber: receipt.blockNumber,
                simulated: false,
            }
        } catch (error) {
            throw new Error(`DID registration failed: ${error.message}`)
        }
    }

    /**
     * Resolve a DID from the on-chain registry.
     */
    async resolveDID(did) {
        this._ensureInitialized()
        if (!this.didRegistry) return null

        try {
            const [didDocument, owner, createdAt, active] =
                await this.didRegistry.resolveDID(did)
            return {
                didDocument: JSON.parse(didDocument),
                owner,
                createdAt: Number(createdAt),
                active,
            }
        } catch (error) {
            throw new Error(`DID resolution failed: ${error.message}`)
        }
    }

    // ─── Credential Operations ───────────────────────────────────────

    /**
     * Anchor a credential hash on-chain so it can be verified forever.
     * The hash = keccak256 of the full credential JSON.
     */
    async anchorCredential(credentialId, credentialHash, issuerDID) {
        this._ensureInitialized()
        if (!this.credentialRegistry) {
            console.warn('⚠️  Credential Registry not deployed — simulating anchor')
            return {
                txHash: `0xsim_${Date.now().toString(16)}`,
                blockNumber: 0,
                simulated: true,
            }
        }

        try {
            // Convert string IDs to bytes32 for the contract
            const credIdBytes = ethers.id(credentialId)
            const tx = await this.credentialRegistry.anchorCredential(
                credIdBytes,
                credentialHash,
                issuerDID,
                Math.floor(Date.now() / 1000)
            )
            const receipt = await tx.wait()
            return {
                txHash: receipt.hash,
                blockNumber: receipt.blockNumber,
                simulated: false,
            }
        } catch (error) {
            throw new Error(`Blockchain anchoring failed: ${error.message}`)
        }
    }

    /**
     * Check if a credential has been revoked on-chain.
     */
    async isCredentialRevoked(credentialId) {
        this._ensureInitialized()
        if (!this.revocationRegistry) return false

        try {
            const credIdBytes = ethers.id(credentialId)
            return await this.revocationRegistry.isRevoked(credIdBytes)
        } catch (error) {
            console.error('Revocation check failed:', error.message)
            return false
        }
    }

    /**
     * Revoke a credential on-chain (only callable by the original issuer).
     */
    async revokeCredential(credentialId) {
        this._ensureInitialized()
        if (!this.revocationRegistry) {
            console.warn('⚠️  Revocation Registry not deployed — simulating revoke')
            return { success: true, simulated: true }
        }

        try {
            const credIdBytes = ethers.id(credentialId)
            const tx = await this.revocationRegistry.revokeCredential(credIdBytes)
            const receipt = await tx.wait()
            return {
                success: true,
                txHash: receipt.hash,
                simulated: false,
            }
        } catch (error) {
            throw new Error(`Credential revocation failed: ${error.message}`)
        }
    }

    /**
     * Get the on-chain hash for tamper verification.
     */
    async getAnchoredHash(credentialId) {
        this._ensureInitialized()
        if (!this.credentialRegistry) return null

        try {
            const credIdBytes = ethers.id(credentialId)
            return await this.credentialRegistry.getCredentialHash(credIdBytes)
        } catch (error) {
            console.error('Hash lookup failed:', error.message)
            return null
        }
    }

    // ─── Utility ──────────────────────────────────────────────────────

    /**
     * Get the issuer's Ethereum address (derived from the private key).
     */
    getIssuerAddress() {
        this._ensureInitialized()
        return this.issuerWallet.address
    }

    /**
     * Health check — true if we can reach the RPC node.
     */
    async isConnected() {
        this._ensureInitialized()
        try {
            const blockNumber = await this.provider.getBlockNumber()
            return { connected: true, blockNumber }
        } catch {
            return { connected: false, blockNumber: null }
        }
    }
}

// Export singleton
export default new BlockchainService()
