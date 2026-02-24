// src/modules/presentation/presentation.service.js
// Handles the challenge-response QR verification flow.
//
// Flow:
// 1. Verifier generates a challenge → displayed as QR
// 2. User scans QR → signs challenge + credential → creates Verifiable Presentation
// 3. Verifier receives VP → validates signature, nonce, credential, revocation

import crypto from 'crypto'
import { ethers } from 'ethers'
import credentialService from '../credentials/credential.service.js'

// In-memory challenge store (Redis replacement for dev — swap for ioredis in production)
const challengeStore = new Map()

// Auto-clean expired challenges every 60 seconds
setInterval(() => {
    const now = Date.now()
    for (const [id, challenge] of challengeStore) {
        if (now > challenge.expiresAt) {
            challengeStore.delete(id)
        }
    }
}, 60_000)

export class PresentationService {
    /**
     * VERIFIER SIDE: Generate a challenge nonce.
     * This gets encoded into the QR code the verifier displays.
     */
    async generateChallenge(verifierDID, requestedCredentialTypes = []) {
        const challenge = {
            id: crypto.randomUUID(),
            nonce: crypto.randomUUID(),
            verifierDID,
            requestedCredentialTypes,
            createdAt: Date.now(),
            expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes
        }

        // Store challenge (in production, use Redis with TTL)
        challengeStore.set(challenge.id, challenge)

        // Schedule auto-cleanup
        setTimeout(() => challengeStore.delete(challenge.id), 5 * 60 * 1000)

        return challenge
    }

    /**
     * USER SIDE: Create a Verifiable Presentation from their credentials.
     * This runs on the user's device (or via server proxy).
     */
    async createPresentation({
        holderDID,
        credentials,
        challengeId,
        nonce,
        holderSignature,
    }) {
        // Build the VP
        const presentation = {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: ['VerifiablePresentation'],
            holder: holderDID,
            verifiableCredential: credentials,
            proof: {
                type: 'EcdsaSecp256k1Signature2019',
                created: new Date().toISOString(),
                challenge: nonce,
                domain: challengeId,
                proofPurpose: 'authentication',
                verificationMethod: `${holderDID}#controller`,
                signature: holderSignature,
            },
        }

        return presentation
    }

    /**
     * VERIFIER SIDE: Verify a submitted Verifiable Presentation.
     * This is the critical path — must be fast (< 3 seconds).
     */
    async verifyPresentation(verifiablePresentation, challengeId) {
        const result = {
            presentationValid: false,
            holderDID: null,
            credentialResults: [],
            errors: [],
            grantAccess: false,
            verifiedAt: new Date().toISOString(),
        }

        try {
            // Step 1: Retrieve and validate the challenge
            const challenge = challengeStore.get(challengeId)
            if (!challenge) {
                result.errors.push('Challenge expired or not found')
                return result
            }

            if (Date.now() > challenge.expiresAt) {
                result.errors.push('Challenge has expired')
                challengeStore.delete(challengeId)
                return result
            }

            // Step 2: Validate the VP structure
            if (
                !verifiablePresentation ||
                !verifiablePresentation.holder ||
                !verifiablePresentation.verifiableCredential
            ) {
                result.errors.push('Invalid presentation structure')
                return result
            }

            result.holderDID = verifiablePresentation.holder

            // Step 3: Verify the nonce matches the challenge
            const proof = verifiablePresentation.proof
            if (!proof || proof.challenge !== challenge.nonce) {
                result.errors.push(
                    'Nonce mismatch — possible replay attack or wrong challenge'
                )
                return result
            }

            // Step 4: Verify the holder's signature
            let holderVerified = false
            if (proof.signature) {
                try {
                    // Build the message that was signed
                    const signedPayload = JSON.stringify({
                        holder: verifiablePresentation.holder,
                        challenge: challenge.nonce,
                        domain: challengeId,
                    })
                    const recoveredAddress = ethers.verifyMessage(
                        signedPayload,
                        proof.signature
                    )

                    // Extract address from holder DID
                    const holderAddress =
                        verifiablePresentation.holder.split(':').pop()
                    holderVerified =
                        recoveredAddress.toLowerCase() === holderAddress.toLowerCase()

                    if (!holderVerified) {
                        result.errors.push(
                            'Holder signature mismatch — presenter is not the credential holder'
                        )
                    }
                } catch (err) {
                    result.errors.push(`Signature verification failed: ${err.message}`)
                }
            } else {
                result.errors.push('No holder signature provided')
            }

            // Step 5: Verify each embedded credential individually
            const credentials = Array.isArray(
                verifiablePresentation.verifiableCredential
            )
                ? verifiablePresentation.verifiableCredential
                : [verifiablePresentation.verifiableCredential]

            const credentialResults = await Promise.all(
                credentials.map((vc) => credentialService.verifyCredential(vc))
            )
            result.credentialResults = credentialResults

            // Step 6: Check that credential types match what the verifier requested
            if (
                challenge.requestedCredentialTypes &&
                challenge.requestedCredentialTypes.length > 0
            ) {
                const presentedTypes = credentials.flatMap((vc) => {
                    if (typeof vc === 'string') {
                        try {
                            const decoded = JSON.parse(
                                Buffer.from(vc.split('.')[1], 'base64url').toString()
                            )
                            return decoded.type || []
                        } catch {
                            return []
                        }
                    }
                    return vc.type || []
                })

                const missingTypes = challenge.requestedCredentialTypes.filter(
                    (t) => !presentedTypes.includes(t)
                )
                if (missingTypes.length > 0) {
                    result.errors.push(
                        `Missing requested credential types: ${missingTypes.join(', ')}`
                    )
                }
            }

            // Step 7: Invalidate the challenge — single-use only
            challengeStore.delete(challengeId)

            // Final verdict
            const allCredentialsValid = credentialResults.every((r) => r.isValid)
            result.presentationValid = holderVerified && allCredentialsValid
            result.grantAccess =
                result.presentationValid && result.errors.length === 0
        } catch (error) {
            result.errors.push(`Presentation verification error: ${error.message}`)
        }

        return result
    }

    /**
     * GET CHALLENGE (for debugging/polling)
     */
    getChallenge(challengeId) {
        return challengeStore.get(challengeId) || null
    }
}

export default new PresentationService()
