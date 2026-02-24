// src/routes/credential.routes.js
// REST endpoints for credential issuance, verification, and revocation

import express from 'express'
import credentialService from '../modules/credentials/credential.service.js'
import { authMiddleware } from '../middleware/auth.middleware.js'
import {
    validate,
    issueCredentialSchema,
} from '../middleware/validate.middleware.js'

const router = express.Router()

// ──────────────────────── ISSUER ROUTES ────────────────────────

/**
 * POST /api/credentials/issue
 * Issue a new Verifiable Credential — only authorized issuers can call this.
 */
router.post(
    '/issue',
    authMiddleware('issuer'),
    validate(issueCredentialSchema),
    async (req, res) => {
        try {
            const { subjectDID, credentialType, claims, expiryDate } = req.body
            const result = await credentialService.issueCredential({
                subjectDID,
                credentialType,
                claims,
                expiryDate,
                issuerDID: req.identity.did,
            })

            res.status(201).json({ success: true, data: result })
        } catch (error) {
            console.error('Credential issuance error:', error)
            res.status(500).json({ success: false, error: error.message })
        }
    }
)

// ──────────────────────── PUBLIC ROUTES ────────────────────────

/**
 * POST /api/credentials/verify
 * Verify a credential — public endpoint, anyone can verify.
 */
router.post('/verify', async (req, res) => {
    try {
        const { credential } = req.body
        if (!credential) {
            return res.status(400).json({
                success: false,
                error: 'Credential is required in the request body',
            })
        }

        const result = await credentialService.verifyCredential(credential)
        res.json({ success: true, data: result })
    } catch (error) {
        console.error('Credential verification error:', error)
        res.status(400).json({ success: false, error: error.message })
    }
})

/**
 * GET /api/credentials/:id
 * Get a specific credential by its ID
 */
router.get('/:id', async (req, res) => {
    try {
        const credential = await credentialService.getCredential(req.params.id)
        res.json({ success: true, data: credential })
    } catch (error) {
        res.status(404).json({ success: false, error: error.message })
    }
})

/**
 * GET /api/credentials
 * List credentials with optional filters
 */
router.get('/', authMiddleware(), async (req, res) => {
    try {
        const { issuerDID, subjectDID, status, credentialType, page, limit } =
            req.query
        const result = await credentialService.listCredentials({
            issuerDID,
            subjectDID,
            status,
            credentialType,
            page: parseInt(page) || 1,
            limit: parseInt(limit) || 20,
        })
        res.json({ success: true, data: result })
    } catch (error) {
        res.status(500).json({ success: false, error: error.message })
    }
})

// ──────────────────────── REVOCATION ────────────────────────

/**
 * DELETE /api/credentials/:id/revoke
 * Revoke a credential — only the original issuer can revoke.
 */
router.delete(
    '/:id/revoke',
    authMiddleware('issuer'),
    async (req, res) => {
        try {
            const { reason } = req.body || {}
            const result = await credentialService.revokeCredential(
                req.params.id,
                reason
            )
            res.json({ success: true, data: result })
        } catch (error) {
            console.error('Credential revocation error:', error)
            res.status(500).json({ success: false, error: error.message })
        }
    }
)

export default router
