// tests/unit/credential.service.test.js
// Unit tests for the credential service — mocks blockchain calls

import { jest } from '@jest/globals'

// ─── Mock blockchain service ───────────────────────────────────
const mockBlockchainService = {
    anchorCredential: jest.fn(),
    isCredentialRevoked: jest.fn(),
    getAnchoredHash: jest.fn(),
    revokeCredential: jest.fn(),
    getIssuerAddress: jest.fn(),
    _ensureInitialized: jest.fn(),
}

jest.unstable_mockModule(
    '../../src/services/blockchain.service.js',
    () => ({ default: mockBlockchainService })
)

// ─── Mock Mongoose models ──────────────────────────────────────
const mockCredentialCreate = jest.fn()
const mockCredentialFindOne = jest.fn()
const mockCredentialFind = jest.fn()
const mockCredentialCountDocuments = jest.fn()

jest.unstable_mockModule('../../src/models/Credential.model.js', () => ({
    default: {
        create: mockCredentialCreate,
        findOne: mockCredentialFindOne,
        find: jest.fn(() => ({
            select: jest.fn(() => ({
                skip: jest.fn(() => ({
                    limit: jest.fn(() => ({
                        sort: jest.fn(() => []),
                    })),
                })),
            })),
        })),
        countDocuments: mockCredentialCountDocuments,
    },
}))

jest.unstable_mockModule('../../src/models/Identity.model.js', () => ({
    default: {
        findOne: jest.fn(),
    },
}))

jest.unstable_mockModule('../../src/config/blockchain.config.js', () => ({
    default: {
        network: { name: 'maticmum', chainId: 80001 },
        issuer: {
            privateKey:
                '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
        },
    },
}))

// ─── Import after mocks ────────────────────────────────────────
const { CredentialService } = await import(
    '../../src/modules/credentials/credential.service.js'
)

describe('CredentialService', () => {
    let credentialService

    beforeEach(() => {
        credentialService = new CredentialService()
        jest.clearAllMocks()

        // Default mock return values
        mockBlockchainService.anchorCredential.mockResolvedValue({
            txHash: '0xabc123def456',
            blockNumber: 12345,
            simulated: false,
        })
        mockBlockchainService.isCredentialRevoked.mockResolvedValue(false)
        mockBlockchainService.getAnchoredHash.mockResolvedValue(null)
        mockBlockchainService.getIssuerAddress.mockReturnValue(
            '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'
        )

        mockCredentialCreate.mockImplementation((data) =>
            Promise.resolve({
                ...data,
                _id: 'mock-id',
                createdAt: new Date(),
                updatedAt: new Date(),
            })
        )
    })

    // ─── ISSUANCE TESTS ────────────────────────────────────────

    describe('issueCredential', () => {
        const validInput = {
            subjectDID: 'did:ethr:maticmum:0xAliceDID',
            credentialType: 'DigitalPassCredential',
            claims: {
                name: 'Alice Smith',
                passType: 'premium',
                accessLevel: 'standard',
            },
            expiryDate: new Date(
                Date.now() + 365 * 24 * 60 * 60 * 1000
            ).toISOString(),
            issuerDID: 'did:ethr:maticmum:0xIssuerDID',
        }

        it('returns a credential with correct structure', async () => {
            const result = await credentialService.issueCredential(validInput)

            expect(result.credentialId).toMatch(/^urn:uuid:/)
            expect(result.credential).toBeDefined()
            expect(result.credential.type).toContain('VerifiableCredential')
            expect(result.credential.type).toContain('DigitalPassCredential')
            expect(result.credentialJWT).toBeDefined()
            expect(result.onChainTxHash).toBe('0xabc123def456')
            expect(result.anchoredHash).toBeDefined()
        })

        it('binds credential to the correct subject DID', async () => {
            const result = await credentialService.issueCredential(validInput)

            expect(result.credential.credentialSubject.id).toBe(
                validInput.subjectDID
            )
            expect(result.credential.credentialSubject.name).toBe('Alice Smith')
            expect(result.credential.credentialSubject.passType).toBe('premium')
        })

        it('sets the correct issuer DID', async () => {
            const result = await credentialService.issueCredential(validInput)
            expect(result.credential.issuer).toBe(validInput.issuerDID)
        })

        it('includes issuance and expiration dates', async () => {
            const result = await credentialService.issueCredential(validInput)

            expect(result.credential.issuanceDate).toBeDefined()
            expect(result.credential.expirationDate).toBeDefined()

            const issuance = new Date(result.credential.issuanceDate)
            const expiry = new Date(result.credential.expirationDate)
            expect(expiry > issuance).toBe(true)
        })

        it('calls blockchain service to anchor the hash', async () => {
            await credentialService.issueCredential(validInput)
            expect(mockBlockchainService.anchorCredential).toHaveBeenCalledTimes(1)
        })

        it('persists the credential in MongoDB', async () => {
            await credentialService.issueCredential(validInput)

            expect(mockCredentialCreate).toHaveBeenCalledTimes(1)
            const savedData = mockCredentialCreate.mock.calls[0][0]
            expect(savedData.credentialType).toBe('DigitalPassCredential')
            expect(savedData.subjectDID).toBe(validInput.subjectDID)
            expect(savedData.issuerDID).toBe(validInput.issuerDID)
            expect(savedData.status).toBe('active')
        })

        it('generates a JWT-format credential string', async () => {
            const result = await credentialService.issueCredential(validInput)

            // JWT has 3 parts separated by dots
            const parts = result.credentialJWT.split('.')
            expect(parts.length).toBe(3)

            // Decode header
            const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString())
            expect(header.alg).toBe('ES256K')
            expect(header.typ).toBe('JWT')
        })

        it('still creates credential if blockchain anchoring fails', async () => {
            mockBlockchainService.anchorCredential.mockRejectedValue(
                new Error('Network error')
            )

            const result = await credentialService.issueCredential(validInput)

            // Should still return a credential (anchoring is non-blocking)
            expect(result.credential).toBeDefined()
            expect(result.credentialId).toMatch(/^urn:uuid:/)
            expect(mockCredentialCreate).toHaveBeenCalledTimes(1)
        })
    })

    // ─── VERIFICATION TESTS ────────────────────────────────────

    describe('verifyCredential', () => {
        it('fails verification for expired credentials', async () => {
            const expiredDoc = {
                id: 'urn:uuid:test-expired',
                issuer: 'did:ethr:maticmum:0xIssuer',
                issuanceDate: new Date(Date.now() - 86400_000).toISOString(),
                expirationDate: new Date(Date.now() - 1000).toISOString(),
                type: ['VerifiableCredential', 'DigitalPassCredential'],
                credentialSubject: {
                    id: 'did:ethr:maticmum:0xAlice',
                    name: 'Alice',
                },
            }

            mockCredentialFindOne.mockResolvedValue(null)

            const result = await credentialService.verifyCredential(expiredDoc)

            expect(result.isValid).toBe(false)
            expect(result.checks.notExpired).toBe(false)
            expect(result.errors).toEqual(
                expect.arrayContaining([expect.stringContaining('expired')])
            )
        })

        it('fails verification for revoked credentials', async () => {
            mockBlockchainService.isCredentialRevoked.mockResolvedValue(true)
            mockCredentialFindOne.mockResolvedValue(null)

            const revokedDoc = {
                id: 'urn:uuid:test-revoked',
                issuer: 'did:ethr:maticmum:0xIssuer',
                issuanceDate: new Date().toISOString(),
                expirationDate: new Date(
                    Date.now() + 86400_000
                ).toISOString(),
                type: ['VerifiableCredential'],
                credentialSubject: { id: 'did:ethr:maticmum:0xAlice' },
            }

            const result = await credentialService.verifyCredential(revokedDoc)

            expect(result.checks.notRevoked).toBe(false)
            expect(result.errors).toEqual(
                expect.arrayContaining([expect.stringContaining('revoked')])
            )
        })

        it('returns credential data in the result', async () => {
            mockCredentialFindOne.mockResolvedValue(null)

            const doc = {
                id: 'urn:uuid:test-data',
                issuer: 'did:ethr:maticmum:0xIssuer',
                issuanceDate: new Date().toISOString(),
                expirationDate: new Date(
                    Date.now() + 86400_000
                ).toISOString(),
                type: ['VerifiableCredential', 'DigitalPassCredential'],
                credentialSubject: {
                    id: 'did:ethr:maticmum:0xAlice',
                    name: 'Alice',
                },
            }

            const result = await credentialService.verifyCredential(doc)

            expect(result.credentialData).toBeDefined()
            expect(result.credentialData.id).toBe('urn:uuid:test-data')
            expect(result.credentialData.issuer).toBe(
                'did:ethr:maticmum:0xIssuer'
            )
        })
    })

    // ─── REVOCATION TESTS ──────────────────────────────────────

    describe('revokeCredential', () => {
        it('throws if credential not found', async () => {
            mockCredentialFindOne.mockResolvedValue(null)

            await expect(
                credentialService.revokeCredential('urn:uuid:nonexistent')
            ).rejects.toThrow('Credential not found')
        })

        it('throws if credential is already revoked', async () => {
            mockCredentialFindOne.mockResolvedValue({
                credentialId: 'urn:uuid:already-revoked',
                revocation: { isRevoked: true },
            })

            await expect(
                credentialService.revokeCredential('urn:uuid:already-revoked')
            ).rejects.toThrow('already revoked')
        })

        it('revokes a valid credential', async () => {
            const mockSave = jest.fn()
            mockCredentialFindOne.mockResolvedValue({
                credentialId: 'urn:uuid:to-revoke',
                revocation: { isRevoked: false },
                save: mockSave,
            })
            mockBlockchainService.revokeCredential.mockResolvedValue({
                success: true,
                txHash: '0xrevoke123',
            })

            const result = await credentialService.revokeCredential(
                'urn:uuid:to-revoke',
                'Policy violation'
            )

            expect(result.revoked).toBe(true)
            expect(result.reason).toBe('Policy violation')
            expect(mockSave).toHaveBeenCalled()
        })
    })
})
