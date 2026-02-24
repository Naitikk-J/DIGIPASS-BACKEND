// tests/helpers/auth.helper.js
// Test helper to generate JWT tokens for issuer/holder personas

import jwt from 'jsonwebtoken'

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production'

/**
 * Generate a test JWT for an issuer identity.
 */
export function generateIssuerToken(overrides = {}) {
    const payload = {
        did: overrides.did || 'did:ethr:maticmum:0xTestIssuer',
        role: 'issuer',
        iat: Math.floor(Date.now() / 1000),
        ...overrides,
    }
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' })
}

/**
 * Generate a test JWT for a holder identity.
 */
export function generateHolderToken(overrides = {}) {
    const payload = {
        did: overrides.did || 'did:ethr:maticmum:0xTestHolder',
        role: 'holder',
        iat: Math.floor(Date.now() / 1000),
        ...overrides,
    }
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' })
}

/**
 * Create a mock identity in the database for auth middleware lookups.
 */
export async function createMockIdentity(Identity, overrides = {}) {
    const { ethers } = await import('ethers')
    const wallet = ethers.Wallet.createRandom()

    return Identity.create({
        did: overrides.did || `did:ethr:maticmum:${wallet.address}`,
        address: (overrides.address || wallet.address).toLowerCase(),
        publicKey: overrides.publicKey || wallet.publicKey,
        role: overrides.role || 'holder',
        isActive: true,
        metadata: overrides.metadata || { name: 'Test User' },
        ...overrides,
    })
}
