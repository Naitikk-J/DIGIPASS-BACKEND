// src/routes/health.routes.js
// Health check and system status endpoints

import express from 'express'
import blockchainService from '../services/blockchain.service.js'
import mongoose from 'mongoose'

const router = express.Router()

/**
 * GET /api/health
 * Quick health check — returns 200 if the server is running.
 */
router.get('/', (_req, res) => {
    res.json({
        success: true,
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
    })
})

/**
 * GET /api/health/detailed
 * Detailed health — checks MongoDB and blockchain connectivity.
 */
router.get('/detailed', async (_req, res) => {
    const health = {
        server: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        mongodb: 'unknown',
        blockchain: 'unknown',
    }

    // Check MongoDB
    try {
        const state = mongoose.connection.readyState
        health.mongodb = state === 1 ? 'connected' : 'disconnected'
    } catch {
        health.mongodb = 'error'
    }

    // Check blockchain
    try {
        const bcStatus = await blockchainService.isConnected()
        health.blockchain = bcStatus.connected ? 'connected' : 'disconnected'
        if (bcStatus.blockNumber) {
            health.latestBlock = bcStatus.blockNumber
        }
    } catch {
        health.blockchain = 'error'
    }

    const isHealthy =
        health.mongodb === 'connected' // blockchain can be down in dev

    res
        .status(isHealthy ? 200 : 503)
        .json({ success: isHealthy, data: health })
})

export default router
