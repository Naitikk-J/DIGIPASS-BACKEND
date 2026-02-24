// src/routes/issuer.routes.js
// Issuer-specific management routes (dashboard, stats, credential management)

import express from 'express'
import { authMiddleware } from '../middleware/auth.middleware.js'
import credentialService from '../modules/credentials/credential.service.js'
import identityService from '../modules/identity/identity.service.js'
import Credential from '../models/Credential.model.js'

const router = express.Router()

// All issuer routes require issuer authentication
router.use(authMiddleware('issuer'))

/**
 * GET /api/issuer/dashboard
 * Issuer dashboard stats — number of credentials issued, revoked, active, etc.
 */
router.get('/dashboard', async (req, res) => {
    try {
        const issuerDID = req.identity.did

        const [total, active, revoked, expired] = await Promise.all([
            Credential.countDocuments({ issuerDID }),
            Credential.countDocuments({ issuerDID, status: 'active' }),
            Credential.countDocuments({ issuerDID, status: 'revoked' }),
            Credential.countDocuments({ issuerDID, status: 'expired' }),
        ])

        // Recent credentials (last 10)
        const recentCredentials = await Credential.find({ issuerDID })
            .select('credentialId subjectDID credentialType status createdAt')
            .sort({ createdAt: -1 })
            .limit(10)

        // Credential type breakdown
        const typeBreakdown = await Credential.aggregate([
            { $match: { issuerDID } },
            { $group: { _id: '$credentialType', count: { $sum: 1 } } },
        ])

        res.json({
            success: true,
            data: {
                stats: { total, active, revoked, expired },
                recentCredentials,
                typeBreakdown: typeBreakdown.reduce(
                    (acc, t) => ({ ...acc, [t._id]: t.count }),
                    {}
                ),
            },
        })
    } catch (error) {
        console.error('Dashboard error:', error)
        res.status(500).json({ success: false, error: error.message })
    }
})

/**
 * GET /api/issuer/credentials
 * List all credentials issued by this issuer
 */
router.get('/credentials', async (req, res) => {
    try {
        const { status, credentialType, page, limit } = req.query
        const result = await credentialService.listCredentials({
            issuerDID: req.identity.did,
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

/**
 * GET /api/issuer/profile
 * Get the issuer's own identity profile
 */
router.get('/profile', async (req, res) => {
    try {
        const profile = await identityService.resolveDID(req.identity.did)
        res.json({ success: true, data: profile })
    } catch (error) {
        res.status(500).json({ success: false, error: error.message })
    }
})

export default router
