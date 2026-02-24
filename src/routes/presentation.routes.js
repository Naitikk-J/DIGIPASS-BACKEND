// src/routes/presentation.routes.js
// REST endpoints for the QR-based challenge-response verification flow

import express from 'express'
import presentationService from '../modules/presentation/presentation.service.js'
import { authMiddleware } from '../middleware/auth.middleware.js'
import {
    validate,
    generateChallengeSchema,
    createPresentationSchema,
    verifyPresentationSchema,
} from '../middleware/validate.middleware.js'

const router = express.Router()

// ──────────────── VERIFIER ROUTES ─────────────────

/**
 * POST /api/presentation/challenge
 * Generate a verification challenge — the verifier displays this as a QR code.
 */
router.post(
    '/challenge',
    validate(generateChallengeSchema),
    async (req, res) => {
        try {
            const { verifierDID, requestedCredentialTypes } = req.body
            const challenge = await presentationService.generateChallenge(
                verifierDID,
                requestedCredentialTypes
            )

            res.status(201).json({
                success: true,
                data: challenge,
                // This object gets JSON-encoded into the QR code
                qrPayload: JSON.stringify({
                    type: 'VerificationChallenge',
                    challengeId: challenge.id,
                    nonce: challenge.nonce,
                    verifierDID: challenge.verifierDID,
                    requestedCredentialTypes: challenge.requestedCredentialTypes,
                    expiresAt: challenge.expiresAt,
                }),
            })
        } catch (error) {
            console.error('Challenge generation error:', error)
            res.status(500).json({ success: false, error: error.message })
        }
    }
)

/**
 * GET /api/presentation/challenge/:id
 * Check the status of a challenge (polling endpoint for verifier UI).
 */
router.get('/challenge/:id', async (req, res) => {
    try {
        const challenge = presentationService.getChallenge(req.params.id)
        if (!challenge) {
            return res.status(404).json({
                success: false,
                error: 'Challenge not found or has expired',
            })
        }

        res.json({
            success: true,
            data: {
                id: challenge.id,
                expiresAt: challenge.expiresAt,
                isExpired: Date.now() > challenge.expiresAt,
                timeRemaining: Math.max(
                    0,
                    Math.floor((challenge.expiresAt - Date.now()) / 1000)
                ),
            },
        })
    } catch (error) {
        res.status(500).json({ success: false, error: error.message })
    }
})

// ──────────────── USER/HOLDER ROUTES ──────────────

/**
 * POST /api/presentation/create
 * Create a Verifiable Presentation in response to a challenge.
 * Called by the user's wallet app.
 */
router.post(
    '/create',
    validate(createPresentationSchema),
    async (req, res) => {
        try {
            const { holderDID, credentials, challengeId, nonce, holderSignature } =
                req.body
            const presentation = await presentationService.createPresentation({
                holderDID,
                credentials,
                challengeId,
                nonce,
                holderSignature,
            })

            res.status(201).json({
                success: true,
                data: {
                    presentation,
                    // This gets encoded into the user's QR code for the verifier to scan
                    qrPayload: JSON.stringify({
                        type: 'VerifiablePresentation',
                        presentation,
                        challengeId,
                    }),
                },
            })
        } catch (error) {
            console.error('Presentation creation error:', error)
            res.status(500).json({ success: false, error: error.message })
        }
    }
)

// ──────────────── VERIFICATION ROUTE ──────────────

/**
 * POST /api/presentation/verify
 * Verify a submitted presentation — the verifier calls this after scanning the user's QR.
 */
router.post(
    '/verify',
    validate(verifyPresentationSchema),
    async (req, res) => {
        try {
            const { presentation, challengeId } = req.body
            const result = await presentationService.verifyPresentation(
                presentation,
                challengeId
            )

            // Set appropriate HTTP status based on result
            const status = result.grantAccess ? 200 : 403

            res.status(status).json({
                success: true,
                data: {
                    ...result,
                    accessDecision: result.grantAccess
                        ? 'ACCESS GRANTED'
                        : 'ACCESS DENIED',
                },
            })
        } catch (error) {
            console.error('Presentation verification error:', error)
            res.status(500).json({ success: false, error: error.message })
        }
    }
)

export default router
