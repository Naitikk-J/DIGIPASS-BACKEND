// src/middleware/auth.middleware.js
// JWT-based authentication middleware for issuers.
// Verifiers and public endpoints don't require auth.

import jwt from 'jsonwebtoken'
import Identity from '../models/Identity.model.js'

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me'

/**
 * Factory function — returns middleware configured for a specific role.
 *
 * Usage:
 *   router.post('/issue', authMiddleware('issuer'), handler)
 *   router.get('/admin', authMiddleware('admin'), handler)
 */
export function authMiddleware(requiredRole = null) {
    return async (req, res, next) => {
        try {
            // Extract token from Authorization header
            const authHeader = req.headers.authorization
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({
                    success: false,
                    error: 'Authentication required — provide a Bearer token',
                })
            }

            const token = authHeader.split(' ')[1]

            // Verify JWT
            let decoded
            try {
                decoded = jwt.verify(token, JWT_SECRET)
            } catch (err) {
                if (err.name === 'TokenExpiredError') {
                    return res.status(401).json({
                        success: false,
                        error: 'Token has expired — please log in again',
                    })
                }
                return res.status(401).json({
                    success: false,
                    error: 'Invalid token',
                })
            }

            // Look up identity in database
            const identity = await Identity.findOne({
                did: decoded.did,
                isActive: true,
            })

            if (!identity) {
                return res.status(401).json({
                    success: false,
                    error: 'Identity not found or has been deactivated',
                })
            }

            // Check role if required
            if (requiredRole && identity.role !== requiredRole) {
                return res.status(403).json({
                    success: false,
                    error: `Access denied — requires '${requiredRole}' role, you have '${identity.role}'`,
                })
            }

            // Attach identity info to request for downstream handlers
            req.identity = {
                did: identity.did,
                address: identity.address,
                role: identity.role,
                metadata: identity.metadata,
            }
            req.issuer = req.identity // Alias for backward compat

            next()
        } catch (error) {
            console.error('Auth middleware error:', error)
            return res.status(500).json({
                success: false,
                error: 'Authentication error',
            })
        }
    }
}

/**
 * Generate a JWT token for a DID.
 * Called during login/registration.
 */
export function generateToken(did, role = 'holder') {
    return jwt.sign(
        { did, role, iat: Math.floor(Date.now() / 1000) },
        JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    )
}

/**
 * Optional auth — populates req.identity if a token is present, but doesn't block.
 */
export function optionalAuth() {
    return async (req, _res, next) => {
        try {
            const authHeader = req.headers.authorization
            if (authHeader && authHeader.startsWith('Bearer ')) {
                const token = authHeader.split(' ')[1]
                const decoded = jwt.verify(token, JWT_SECRET)
                const identity = await Identity.findOne({
                    did: decoded.did,
                    isActive: true,
                })
                if (identity) {
                    req.identity = {
                        did: identity.did,
                        address: identity.address,
                        role: identity.role,
                        metadata: identity.metadata,
                    }
                }
            }
        } catch {
            // Silently ignore — optional auth
        }
        next()
    }
}

export default authMiddleware
