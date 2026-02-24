// src/modules/credentials/credential.service.js
// Core business logic for issuing, verifying, and revoking Verifiable Credentials.
// Uses ethers.js for hashing/signing and the blockchain service for on-chain anchoring.

import { ethers } from 'ethers'
import crypto from 'crypto'
import Credential from '../../models/Credential.model.js'
import blockchainService from '../../services/blockchain.service.js'
import blockchainConfig from '../../config/blockchain.config.js'

export class CredentialService {
    /**
     * ISSUE A CREDENTIAL
     *
     * 4-step process:
     * 1. Build the W3C-compliant VC structure
     * 2. Sign it with the issuer's key (JWT-style with ethers)
     * 3. Compute hash and anchor on-chain
     * 4. Persist in MongoDB and return the signed credential
     */
    async issueCredential({
        subjectDID,
        credentialType,
        claims,
        expiryDate,
        issuerDID,
    }) {
        // Generate unique credential ID
        const credentialId = `urn:uuid:${crypto.randomUUID()}`

        // Step 1: Build W3C VC data model
        const credentialDocument = {
            '@context': [
                'https://www.w3.org/2018/credentials/v1',
                'https://schema.org',
            ],
            id: credentialId,
            type: ['VerifiableCredential', credentialType],
            issuer: issuerDID,
            issuanceDate: new Date().toISOString(),
            expirationDate: new Date(expiryDate).toISOString(),
            credentialSubject: {
                id: subjectDID,
                ...claims,
            },
        }

        // Step 2: Sign the credential document (JWT-style hash + signature)
        const credentialJSON = JSON.stringify(credentialDocument)
        const credentialHash = ethers.keccak256(ethers.toUtf8Bytes(credentialJSON))

        // Create a signing payload (issuer proves they created this)
        const signingPayload = {
            credentialId,
            credentialHash,
            issuerDID,
            issuanceTimestamp: Math.floor(Date.now() / 1000),
        }

        // Build a JWT-like structure: header.payload.signature
        const header = Buffer.from(
            JSON.stringify({ alg: 'ES256K', typ: 'JWT' })
        ).toString('base64url')
        const payload = Buffer.from(JSON.stringify(credentialDocument)).toString(
            'base64url'
        )

        // The issuer wallet signs the hash to prove authorship
        let signature = ''
        try {
            const issuerWallet = new ethers.Wallet(
                blockchainConfig.issuer.privateKey
            )
            signature = await issuerWallet.signMessage(credentialHash)
        } catch (err) {
            console.warn('⚠️  Could not sign with issuer key, using placeholder')
            signature = `sig_placeholder_${Date.now()}`
        }

        const credentialJWT = `${header}.${payload}.${Buffer.from(signature).toString('base64url')}`

        // Step 3: Anchor on-chain
        let onChainResult = { txHash: null, simulated: true }
        try {
            onChainResult = await blockchainService.anchorCredential(
                credentialId,
                credentialHash,
                issuerDID
            )
        } catch (err) {
            console.warn(`⚠️  On-chain anchoring skipped: ${err.message}`)
        }

        // Step 4: Persist in MongoDB
        const credentialRecord = await Credential.create({
            credentialId,
            issuerDID,
            subjectDID,
            credentialType,
            claims,
            credentialJWT,
            credentialDocument,
            issuanceDate: new Date(),
            expirationDate: new Date(expiryDate),
            onChain: {
                txHash: onChainResult.txHash,
                blockNumber: onChainResult.blockNumber,
                credentialHash,
                anchoredAt: onChainResult.txHash ? new Date() : null,
            },
            status: 'active',
        })

        return {
            credentialId,
            credential: credentialDocument,
            credentialJWT,
            onChainTxHash: onChainResult.txHash,
            anchoredHash: credentialHash,
            issuanceDate: credentialRecord.issuanceDate,
            expirationDate: credentialRecord.expirationDate,
        }
    }

    /**
     * VERIFY A CREDENTIAL
     *
     * 3-layer verification:
     * Layer 1: Cryptographic — is the JWT signature valid?
     * Layer 2: Temporal — is it expired?
     * Layer 3: Blockchain — is it revoked? Does the on-chain hash match?
     */
    async verifyCredential(credentialJWTOrDoc) {
        const result = {
            isValid: false,
            checks: {
                signatureValid: false,
                notExpired: false,
                notRevoked: false,
                hashMatches: false,
                issuerTrusted: false,
            },
            credentialData: null,
            errors: [],
        }

        try {
            let credentialDocument
            let credentialJWT

            // Parse JWT if provided as string
            if (typeof credentialJWTOrDoc === 'string' && credentialJWTOrDoc.includes('.')) {
                credentialJWT = credentialJWTOrDoc
                const parts = credentialJWT.split('.')
                if (parts.length !== 3) {
                    result.errors.push('Invalid JWT structure')
                    return result
                }
                try {
                    credentialDocument = JSON.parse(
                        Buffer.from(parts[1], 'base64url').toString()
                    )
                } catch {
                    result.errors.push('Failed to decode JWT payload')
                    return result
                }
            } else if (typeof credentialJWTOrDoc === 'object') {
                credentialDocument = credentialJWTOrDoc
                // Look up the JWT from MongoDB
                const record = await Credential.findOne({
                    credentialId: credentialJWTOrDoc.id,
                })
                credentialJWT = record?.credentialJWT
            } else {
                result.errors.push('Invalid credential format')
                return result
            }

            result.credentialData = {
                id: credentialDocument.id,
                type: credentialDocument.type,
                issuer: credentialDocument.issuer,
                subject: credentialDocument.credentialSubject,
                issuanceDate: credentialDocument.issuanceDate,
                expirationDate: credentialDocument.expirationDate,
            }

            // Layer 1: Signature verification
            if (credentialJWT) {
                const parts = credentialJWT.split('.')
                const payloadJSON = JSON.stringify(credentialDocument)
                const computedHash = ethers.keccak256(ethers.toUtf8Bytes(payloadJSON))

                try {
                    const signatureRaw = Buffer.from(parts[2], 'base64url').toString()
                    const recoveredAddress = ethers.verifyMessage(
                        computedHash,
                        signatureRaw
                    )
                    // Check against known issuer address
                    const issuerAddress = blockchainService.getIssuerAddress()
                    result.checks.signatureValid =
                        recoveredAddress.toLowerCase() === issuerAddress.toLowerCase()
                } catch {
                    // If signature verification fails, mark as invalid but don't crash
                    result.checks.signatureValid = false
                    result.errors.push('Signature verification failed — credential may be tampered')
                }
            }

            // Layer 2: Expiry check
            if (credentialDocument.expirationDate) {
                const expiry = new Date(credentialDocument.expirationDate)
                result.checks.notExpired = expiry > new Date()
                if (!result.checks.notExpired) {
                    result.errors.push(`Credential expired on ${expiry.toISOString()}`)
                }
            } else {
                result.checks.notExpired = true // No expiry = never expires
            }

            // Layer 3a: On-chain revocation check
            const credentialId = credentialDocument.id
            if (credentialId) {
                const isRevoked =
                    await blockchainService.isCredentialRevoked(credentialId)
                result.checks.notRevoked = !isRevoked
                if (isRevoked) {
                    result.errors.push('Credential has been revoked by the issuer')
                }
            } else {
                result.checks.notRevoked = true
            }

            // Layer 3b: Hash integrity verification
            const currentHash = ethers.keccak256(
                ethers.toUtf8Bytes(JSON.stringify(credentialDocument))
            )
            const anchoredHash =
                await blockchainService.getAnchoredHash(credentialId)

            if (anchoredHash && anchoredHash !== ethers.ZeroHash) {
                result.checks.hashMatches = currentHash === anchoredHash
                if (!result.checks.hashMatches) {
                    result.errors.push(
                        'Credential hash mismatch — data integrity compromised'
                    )
                }
            } else {
                // No on-chain hash to compare (contract not deployed or credential not anchored)
                result.checks.hashMatches = true
            }

            // Issuer trust: check MongoDB for known issuers
            if (credentialDocument.issuer) {
                const { default: Identity } = await import(
                    '../../models/Identity.model.js'
                )
                const issuer = await Identity.findOne({
                    did: credentialDocument.issuer,
                    role: 'issuer',
                    isActive: true,
                })
                result.checks.issuerTrusted = !!issuer
                if (!result.checks.issuerTrusted) {
                    result.errors.push('Issuer is not in the trusted registry')
                }
            }

            // Only valid if ALL checks pass
            result.isValid = Object.values(result.checks).every(
                (check) => check === true
            )
        } catch (error) {
            result.errors.push(`Verification error: ${error.message}`)
        }

        return result
    }

    /**
     * REVOKE A CREDENTIAL
     */
    async revokeCredential(credentialId, reason = 'Issuer revocation') {
        // Update MongoDB
        const credential = await Credential.findOne({ credentialId })
        if (!credential) throw new Error(`Credential not found: ${credentialId}`)
        if (credential.revocation?.isRevoked) {
            throw new Error('Credential is already revoked')
        }

        // Revoke on-chain
        let revokeResult = { simulated: true }
        try {
            revokeResult = await blockchainService.revokeCredential(credentialId)
        } catch (err) {
            console.warn(`⚠️  On-chain revocation skipped: ${err.message}`)
        }

        credential.revocation = {
            isRevoked: true,
            revokedAt: new Date(),
            reason,
            revocationTxHash: revokeResult.txHash || null,
        }
        credential.status = 'revoked'
        await credential.save()

        return {
            credentialId,
            revoked: true,
            reason,
            txHash: revokeResult.txHash || null,
        }
    }

    /**
     * GET CREDENTIAL BY ID
     */
    async getCredential(credentialId) {
        const credential = await Credential.findOne({ credentialId })
        if (!credential) throw new Error(`Credential not found: ${credentialId}`)
        return credential
    }

    /**
     * LIST CREDENTIALS (with filters)
     */
    async listCredentials({
        issuerDID,
        subjectDID,
        status,
        credentialType,
        page = 1,
        limit = 20,
    } = {}) {
        const filter = {}
        if (issuerDID) filter.issuerDID = issuerDID
        if (subjectDID) filter.subjectDID = subjectDID
        if (status) filter.status = status
        if (credentialType) filter.credentialType = credentialType

        const skip = (page - 1) * limit
        const [credentials, total] = await Promise.all([
            Credential.find(filter)
                .select('-credentialJWT') // Don't expose JWT in list view
                .skip(skip)
                .limit(limit)
                .sort({ createdAt: -1 }),
            Credential.countDocuments(filter),
        ])

        return {
            credentials,
            pagination: { page, limit, total, pages: Math.ceil(total / limit) },
        }
    }
}

export default new CredentialService()
