// tests/unit/presentation.service.test.js
// Unit tests for the presentation/QR challenge-response flow

import { jest } from '@jest/globals'

// ─── Mock credential service ──────────────────────────────────
const mockVerifyCredential = jest.fn()

jest.unstable_mockModule(
    '../../src/modules/credentials/credential.service.js',
    () => ({
        default: { verifyCredential: mockVerifyCredential },
        CredentialService: class {
            verifyCredential = mockVerifyCredential
        },
    })
)

jest.unstable_mockModule('../../src/services/blockchain.service.js', () => ({
    default: {
        _ensureInitialized: jest.fn(),
        getIssuerAddress: jest.fn(() => '0x0000000000000000000000000000000000000001'),
    },
}))

jest.unstable_mockModule('../../src/config/blockchain.config.js', () => ({
    default: {
        network: { name: 'maticmum', chainId: 80001 },
        issuer: { privateKey: '0x01' },
    },
}))

const { PresentationService } = await import(
    '../../src/modules/presentation/presentation.service.js'
)

describe('PresentationService', () => {
    let presentationService

    beforeEach(() => {
        presentationService = new PresentationService()
        jest.clearAllMocks()
    })

    // ─── CHALLENGE GENERATION ──────────────────────────────────

    describe('generateChallenge', () => {
        it('returns a challenge with required fields', async () => {
            const challenge = await presentationService.generateChallenge(
                'did:ethr:maticmum:0xVerifier',
                ['DigitalPassCredential']
            )

            expect(challenge.id).toBeDefined()
            expect(challenge.nonce).toBeDefined()
            expect(challenge.verifierDID).toBe('did:ethr:maticmum:0xVerifier')
            expect(challenge.requestedCredentialTypes).toEqual([
                'DigitalPassCredential',
            ])
            expect(challenge.createdAt).toBeDefined()
            expect(challenge.expiresAt).toBeDefined()
        })

        it('sets expiry to 5 minutes in the future', async () => {
            const before = Date.now()
            const challenge = await presentationService.generateChallenge(
                'did:ethr:maticmum:0xVerifier'
            )
            const after = Date.now()

            const expectedMin = before + 5 * 60 * 1000
            const expectedMax = after + 5 * 60 * 1000

            expect(challenge.expiresAt).toBeGreaterThanOrEqual(expectedMin)
            expect(challenge.expiresAt).toBeLessThanOrEqual(expectedMax)
        })

        it('generates unique challenges each time', async () => {
            const c1 = await presentationService.generateChallenge('did:ethr:maticmum:0xV1')
            const c2 = await presentationService.generateChallenge('did:ethr:maticmum:0xV2')

            expect(c1.id).not.toBe(c2.id)
            expect(c1.nonce).not.toBe(c2.nonce)
        })

        it('can be retrieved after generation', async () => {
            const challenge = await presentationService.generateChallenge(
                'did:ethr:maticmum:0xVerifier'
            )
            const retrieved = presentationService.getChallenge(challenge.id)

            expect(retrieved).not.toBeNull()
            expect(retrieved.id).toBe(challenge.id)
            expect(retrieved.nonce).toBe(challenge.nonce)
        })
    })

    // ─── PRESENTATION CREATION ─────────────────────────────────

    describe('createPresentation', () => {
        it('creates a VP with correct structure', async () => {
            const vp = await presentationService.createPresentation({
                holderDID: 'did:ethr:maticmum:0xAlice',
                credentials: [{ type: ['VerifiableCredential'], id: 'urn:uuid:test' }],
                challengeId: 'test-challenge-id',
                nonce: 'test-nonce',
                holderSignature: '0xsignature123',
            })

            expect(vp.type).toContain('VerifiablePresentation')
            expect(vp.holder).toBe('did:ethr:maticmum:0xAlice')
            expect(vp.verifiableCredential).toHaveLength(1)
            expect(vp.proof).toBeDefined()
            expect(vp.proof.challenge).toBe('test-nonce')
            expect(vp.proof.domain).toBe('test-challenge-id')
            expect(vp.proof.signature).toBe('0xsignature123')
        })
    })

    // ─── PRESENTATION VERIFICATION ─────────────────────────────

    describe('verifyPresentation', () => {
        it('rejects when challenge is not found', async () => {
            const result = await presentationService.verifyPresentation(
                { holder: 'did:ethr:maticmum:0xAlice' },
                'nonexistent-challenge-id'
            )

            expect(result.presentationValid).toBe(false)
            expect(result.grantAccess).toBe(false)
            expect(result.errors).toEqual(
                expect.arrayContaining([
                    expect.stringContaining('Challenge expired or not found'),
                ])
            )
        })

        it('rejects when presentation structure is invalid', async () => {
            const challenge = await presentationService.generateChallenge(
                'did:ethr:maticmum:0xVerifier'
            )

            const result = await presentationService.verifyPresentation(
                { holder: null, verifiableCredential: null },
                challenge.id
            )

            expect(result.presentationValid).toBe(false)
            expect(result.errors).toEqual(
                expect.arrayContaining([
                    expect.stringContaining('Invalid presentation structure'),
                ])
            )
        })

        it('rejects when nonce does not match', async () => {
            const challenge = await presentationService.generateChallenge(
                'did:ethr:maticmum:0xVerifier'
            )

            const fakeVP = {
                holder: 'did:ethr:maticmum:0xAlice',
                verifiableCredential: [{ id: 'urn:uuid:test' }],
                proof: {
                    challenge: 'wrong-nonce', // ← doesn't match
                    domain: challenge.id,
                    signature: '0xsig',
                },
            }

            const result = await presentationService.verifyPresentation(
                fakeVP,
                challenge.id
            )

            expect(result.presentationValid).toBe(false)
            expect(result.errors).toEqual(
                expect.arrayContaining([
                    expect.stringContaining('Nonce mismatch'),
                ])
            )
        })

        it('invalidates challenge after use (single-use)', async () => {
            const challenge = await presentationService.generateChallenge(
                'did:ethr:maticmum:0xVerifier'
            )

            mockVerifyCredential.mockResolvedValue({ isValid: true })

            const vp = {
                holder: 'did:ethr:maticmum:0xAlice',
                verifiableCredential: [{ id: 'urn:uuid:test' }],
                proof: {
                    challenge: challenge.nonce,
                    domain: challenge.id,
                    signature: '0xsig',
                },
            }

            // First use
            await presentationService.verifyPresentation(vp, challenge.id)

            // Second use — challenge should be gone
            const result2 = await presentationService.verifyPresentation(
                vp,
                challenge.id
            )
            expect(result2.errors).toEqual(
                expect.arrayContaining([
                    expect.stringContaining('Challenge expired or not found'),
                ])
            )
        })
    })
})
