// src/routes/identity.routes.js
// REST endpoints for DID management

import express from 'express'
import identityService from '../modules/identity/identity.service.js'
import { authMiddleware, generateToken } from '../middleware/auth.middleware.js'
import {
    validate,
    createDIDSchema,
    registerIssuerSchema,
    connectWalletSchema,
} from '../middleware/validate.middleware.js'

const router = express.Router()

// ──────────────────────── PUBLIC ROUTES ────────────────────────

/**
 * POST /api/identity/create
 * Create a new DID (for holders)
 */
router.post('/create', validate(createDIDSchema), async (req, res) => {
    try {
        const result = await identityService.createDID(req.body)

        // Generate JWT token so the new identity can authenticate
        const token = generateToken(result.did, req.body.role || 'holder')

        res.status(201).json({
            success: true,
            data: {
                did: result.did,
                address: result.address,
                publicKey: result.publicKey,
                privateKey: result.privateKey, // ⚠️ Only returned at creation — store securely
                didDocument: result.didDocument,
                onChain: result.onChain,
                token,
            },
        })
    } catch (error) {
        console.error('DID creation error:', error)
        res.status(500).json({ success: false, error: error.message })
    }
})

/**
 * POST /api/identity/issuer/register
 * Register a new issuer identity
 */
router.post(
    '/issuer/register',
    validate(registerIssuerSchema),
    async (req, res) => {
        try {
            const result = await identityService.registerIssuer(req.body)
            const token = generateToken(result.did, 'issuer')

            res.status(201).json({
                success: true,
                data: {
                    did: result.did,
                    address: result.address,
                    publicKey: result.publicKey,
                    privateKey: result.privateKey,
                    token,
                },
            })
        } catch (error) {
            console.error('Issuer registration error:', error)
            res.status(500).json({ success: false, error: error.message })
        }
    }
)

/**
 * GET /api/identity/resolve/:did
 * Resolve a DID to its document (public)
 */
router.get('/resolve/:did(*)', async (req, res) => {
    try {
        const result = await identityService.resolveDID(req.params.did)
        res.json({ success: true, data: result })
    } catch (error) {
        res.status(404).json({ success: false, error: error.message })
    }
})

// ────────────────── WALLET CONNECTION ROUTES ─────────────────

/**
 * GET /api/identity/wallet/nonce/:address
 * 
 * Step 1 of "Sign-In with Ethereum" (SIWE):
 * Returns a human-readable message for the user to sign in MetaMask.
 * The message contains a random nonce that expires in 10 minutes.
 */
router.get('/wallet/nonce/:address', async (req, res) => {
    try {
        const result = await identityService.generateNonce(req.params.address)
        res.json({
            success: true,
            data: result,
        })
    } catch (error) {
        res.status(400).json({ success: false, error: error.message })
    }
})

/**
 * POST /api/identity/wallet/connect
 * 
 * Step 2 of "Sign-In with Ethereum" (SIWE):
 * The frontend sends:
 *   - address:   the user's Ethereum address
 *   - signature: the wallet's signature of the nonce message
 *   - message:   the exact message that was signed
 * 
 * The backend verifies the signature, creates or retrieves the DID,
 * and returns a JWT token for authenticated API access.
 */
router.post(
    '/wallet/connect',
    validate(connectWalletSchema),
    async (req, res) => {
        try {
            const { address, signature, message } = req.body
            const result = await identityService.connectWallet({
                address,
                signature,
                message,
            })

            // Generate JWT for the connected wallet
            const token = generateToken(result.did, result.role)

            res.status(result.isNewIdentity ? 201 : 200).json({
                success: true,
                data: {
                    did: result.did,
                    address: result.address,
                    role: result.role,
                    isNewIdentity: result.isNewIdentity,
                    didDocument: result.didDocument,
                    token,
                },
                message: result.isNewIdentity
                    ? 'Wallet connected — new identity created'
                    : 'Wallet connected — welcome back',
            })
        } catch (error) {
            console.error('Wallet connection error:', error)
            const status = error.message.includes('expired')
                ? 410
                : error.message.includes('mismatch') ||
                    error.message.includes('not proven')
                    ? 401
                    : 400
            res.status(status).json({ success: false, error: error.message })
        }
    }
)

/**
 * GET /api/identity/wallet/address/:address
 * Resolve a DID by Ethereum address (public)
 */
router.get('/wallet/address/:address', async (req, res) => {
    try {
        const result = await identityService.resolveByAddress(req.params.address)
        res.json({ success: true, data: result })
    } catch (error) {
        res.status(404).json({ success: false, error: error.message })
    }
})

// ──────────────────── AUTHENTICATED ROUTES ───────────────────

/**
 * GET /api/identity/list
 * List all identities (requires auth)
 */
router.get('/list', authMiddleware('issuer'), async (req, res) => {
    try {
        const { role, page, limit } = req.query
        const result = await identityService.listDIDs({
            role,
            page: parseInt(page) || 1,
            limit: parseInt(limit) || 20,
        })
        res.json({ success: true, data: result })
    } catch (error) {
        res.status(500).json({ success: false, error: error.message })
    }
})

/**
 * DELETE /api/identity/:did
 * Deactivate a DID (requires auth, self-only or issuer)
 */
router.delete('/:did(*)', authMiddleware(), async (req, res) => {
    try {
        // Only allow deactivating your own DID (or issuer can deactivate anyone)
        if (
            req.identity.did !== req.params.did &&
            req.identity.role !== 'issuer'
        ) {
            return res.status(403).json({
                success: false,
                error: 'You can only deactivate your own identity',
            })
        }

        const result = await identityService.deactivateDID(req.params.did)
        res.json({ success: true, data: result })
    } catch (error) {
        res.status(500).json({ success: false, error: error.message })
    }
})

export default router
