// src/modules/identity/identity.service.js
// Handles DID creation, resolution, wallet connection, and management.
// Each user/issuer gets a did:ethr DID derived from an Ethereum key pair.

import { ethers } from 'ethers'
import crypto from 'crypto'
import Identity from '../../models/Identity.model.js'
import blockchainService from '../../services/blockchain.service.js'
import blockchainConfig from '../../config/blockchain.config.js'

// ─── Nonce store for wallet sign-in challenges ─────────────────
// In production, swap this for Redis with TTL
const nonceStore = new Map()

// Auto-clean expired nonces every 60 seconds
setInterval(() => {
    const now = Date.now()
    for (const [key, entry] of nonceStore) {
        if (now > entry.expiresAt) nonceStore.delete(key)
    }
}, 60_000)

export class IdentityService {
    /**
     * CREATE A NEW DID
     *
     * 1. Generate a new secp256k1 key pair
     * 2. Derive the DID from the Ethereum address
     * 3. Build a minimal DID Document
     * 4. Persist to MongoDB
     * 5. Optionally anchor on-chain
     */
    async createDID({ role = 'holder', metadata = {} } = {}) {
        // Generate key pair
        const wallet = ethers.Wallet.createRandom()
        const networkName = blockchainConfig.network.name
        const did = `did:ethr:${networkName}:${wallet.address}`

        // Build W3C DID Document
        const didDocument = {
            '@context': [
                'https://www.w3.org/ns/did/v1',
                'https://w3id.org/security/suites/secp256k1recovery-2020/v2',
            ],
            id: did,
            verificationMethod: [
                {
                    id: `${did}#controller`,
                    type: 'EcdsaSecp256k1RecoveryMethod2020',
                    controller: did,
                    blockchainAccountId: `eip155:${blockchainConfig.network.chainId}:${wallet.address}`,
                },
            ],
            authentication: [`${did}#controller`],
            assertionMethod: [`${did}#controller`],
        }

        // Persist in MongoDB
        const identity = await Identity.create({
            did,
            address: wallet.address.toLowerCase(),
            publicKey: wallet.publicKey,
            didDocument,
            role,
            metadata,
            isActive: true,
        })

        // Attempt on-chain registration (non-blocking — don't fail if blockchain is down)
        let onChainResult = { simulated: true }
        try {
            onChainResult = await blockchainService.registerDID(
                did,
                wallet.address,
                didDocument
            )
            if (onChainResult.txHash) {
                identity.onChain = {
                    txHash: onChainResult.txHash,
                    blockNumber: onChainResult.blockNumber,
                    registeredAt: new Date(),
                }
                await identity.save()
            }
        } catch (err) {
            console.warn(`⚠️  On-chain DID registration skipped: ${err.message}`)
        }

        return {
            did,
            address: wallet.address,
            publicKey: wallet.publicKey,
            privateKey: wallet.privateKey, // ⚠️  Return ONLY for wallet-side storage — never persist server-side
            didDocument,
            onChain: onChainResult,
        }
    }

    /**
     * RESOLVE A DID
     * Look up by DID string — first in MongoDB, optionally cross-check on-chain.
     */
    async resolveDID(did) {
        const identity = await Identity.findOne({ did, isActive: true })
        if (!identity) {
            throw new Error(`DID not found: ${did}`)
        }

        return {
            did: identity.did,
            address: identity.address,
            publicKey: identity.publicKey,
            didDocument: identity.didDocument,
            role: identity.role,
            metadata: identity.metadata,
            isActive: identity.isActive,
            onChain: identity.onChain,
            createdAt: identity.createdAt,
        }
    }

    /**
     * LIST ALL DIDS (with optional role filter)
     */
    async listDIDs({ role, page = 1, limit = 20 } = {}) {
        const filter = { isActive: true }
        if (role) filter.role = role

        const skip = (page - 1) * limit
        const [identities, total] = await Promise.all([
            Identity.find(filter).skip(skip).limit(limit).sort({ createdAt: -1 }),
            Identity.countDocuments(filter),
        ])

        return {
            identities: identities.map((i) => ({
                did: i.did,
                address: i.address,
                role: i.role,
                metadata: i.metadata,
                isActive: i.isActive,
                createdAt: i.createdAt,
            })),
            pagination: {
                page,
                limit,
                total,
                pages: Math.ceil(total / limit),
            },
        }
    }

    /**
     * DEACTIVATE A DID (soft delete)
     */
    async deactivateDID(did) {
        const identity = await Identity.findOne({ did })
        if (!identity) throw new Error(`DID not found: ${did}`)

        identity.isActive = false
        await identity.save()

        return { did, deactivated: true }
    }

    /**
     * REGISTER AN ISSUER — creates a DID with role='issuer' and extra metadata
     */
    async registerIssuer({ organizationName, email, name }) {
        return this.createDID({
            role: 'issuer',
            metadata: {
                name: name || organizationName,
                organization: organizationName,
                email,
            },
        })
    }

    // ─── WALLET CONNECTION ─────────────────────────────────────

    /**
     * GENERATE A SIGN-IN NONCE
     *
     * The frontend calls this with the user's Ethereum address.
     * We return a human-readable message containing a random nonce.
     * The user signs this message in MetaMask (or any wallet), proving
     * they own the private key for that address.
     */
    async generateNonce(address) {
        if (!ethers.isAddress(address)) {
            throw new Error('Invalid Ethereum address')
        }

        const nonce = crypto.randomUUID()
        const timestamp = Date.now()
        const message = [
            'Welcome to DIGIPASS!',
            '',
            'Sign this message to verify your wallet ownership.',
            'This will NOT trigger a blockchain transaction or cost any gas.',
            '',
            `Wallet:  ${address}`,
            `Nonce:   ${nonce}`,
            `Issued:  ${new Date(timestamp).toISOString()}`,
        ].join('\n')

        // Store nonce with 10-minute expiry
        nonceStore.set(address.toLowerCase(), {
            nonce,
            message,
            createdAt: timestamp,
            expiresAt: timestamp + 10 * 60 * 1000,
        })

        return { message, nonce, expiresIn: 600 }
    }

    /**
     * CONNECT WALLET
     *
     * The core sign-in-with-Ethereum flow:
     * 1. Verify the signature recovers to the claimed address
     * 2. Verify the nonce hasn't expired or been used
     * 3. Create a new DID if first time, or retrieve existing one
     * 4. Return the DID + JWT token
     */
    async connectWallet({ address, signature, message }) {
        const normalizedAddress = address.toLowerCase()

        // Step 1: Verify the nonce exists and hasn't expired
        const storedNonce = nonceStore.get(normalizedAddress)
        if (!storedNonce) {
            throw new Error(
                'No sign-in challenge found for this address — request a nonce first'
            )
        }
        if (Date.now() > storedNonce.expiresAt) {
            nonceStore.delete(normalizedAddress)
            throw new Error('Sign-in challenge has expired — request a new nonce')
        }

        // Step 2: Verify the signed message matches what we issued
        if (message !== storedNonce.message) {
            throw new Error('Message mismatch — sign the exact message from the nonce endpoint')
        }

        // Step 3: Recover the signer's address from the signature
        let recoveredAddress
        try {
            recoveredAddress = ethers.verifyMessage(message, signature)
        } catch (err) {
            throw new Error(`Signature verification failed: ${err.message}`)
        }

        if (recoveredAddress.toLowerCase() !== normalizedAddress) {
            throw new Error(
                'Signature does not match the claimed address — wallet ownership not proven'
            )
        }

        // Step 4: Invalidate the nonce (single-use — prevents replay attacks)
        nonceStore.delete(normalizedAddress)

        // Step 5: Look up existing identity or create a new one
        let identity = await Identity.findOne({
            address: normalizedAddress,
            isActive: true,
        })

        let isNewIdentity = false

        if (!identity) {
            // First time connecting this wallet — create a DID
            isNewIdentity = true
            const networkName = blockchainConfig.network.name
            const did = `did:ethr:${networkName}:${recoveredAddress}`

            const didDocument = {
                '@context': [
                    'https://www.w3.org/ns/did/v1',
                    'https://w3id.org/security/suites/secp256k1recovery-2020/v2',
                ],
                id: did,
                verificationMethod: [
                    {
                        id: `${did}#controller`,
                        type: 'EcdsaSecp256k1RecoveryMethod2020',
                        controller: did,
                        blockchainAccountId: `eip155:${blockchainConfig.network.chainId}:${recoveredAddress}`,
                    },
                ],
                authentication: [`${did}#controller`],
                assertionMethod: [`${did}#controller`],
            }

            identity = await Identity.create({
                did,
                address: normalizedAddress,
                publicKey: '', // We don't have the public key from just a signature
                didDocument,
                role: 'holder',
                isActive: true,
                metadata: { connectedAt: new Date().toISOString() },
            })

            // Attempt on-chain registration
            try {
                const onChainResult = await blockchainService.registerDID(
                    did,
                    recoveredAddress,
                    didDocument
                )
                if (onChainResult.txHash) {
                    identity.onChain = {
                        txHash: onChainResult.txHash,
                        blockNumber: onChainResult.blockNumber,
                        registeredAt: new Date(),
                    }
                    await identity.save()
                }
            } catch (err) {
                console.warn(`⚠️  On-chain DID registration skipped: ${err.message}`)
            }
        }

        return {
            did: identity.did,
            address: identity.address,
            role: identity.role,
            isNewIdentity,
            metadata: identity.metadata,
            didDocument: identity.didDocument,
        }
    }

    /**
     * RESOLVE BY ADDRESS — look up a DID by Ethereum address
     */
    async resolveByAddress(address) {
        const identity = await Identity.findOne({
            address: address.toLowerCase(),
            isActive: true,
        })
        if (!identity) {
            throw new Error(`No identity found for address: ${address}`)
        }

        return {
            did: identity.did,
            address: identity.address,
            role: identity.role,
            metadata: identity.metadata,
            isActive: identity.isActive,
            createdAt: identity.createdAt,
        }
    }
}

export default new IdentityService()
