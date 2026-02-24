// tests/integration/api.test.js
// Integration tests — spins up the Express server and hits real endpoints.
// MongoDB is mocked so tests run without a database.

import { jest } from '@jest/globals'

// ─── Mock the database and heavy dependencies ───────────────

jest.unstable_mockModule('mongoose', () => {
    const mockModel = (name) => {
        const Model = function (data) {
            Object.assign(this, data)
            this.save = jest.fn(() => Promise.resolve(this))
        }
        Model.modelName = name
        Model.create = jest.fn((data) => {
            const doc = new Model(data)
            doc._id = 'mock-id-' + Date.now()
            doc.createdAt = new Date()
            doc.updatedAt = new Date()
            return Promise.resolve(doc)
        })
        Model.findOne = jest.fn(() => Promise.resolve(null))
        Model.find = jest.fn(() => ({
            select: jest.fn(() => ({
                skip: jest.fn(() => ({
                    limit: jest.fn(() => ({
                        sort: jest.fn(() => Promise.resolve([])),
                    })),
                })),
            })),
            skip: jest.fn(() => ({
                limit: jest.fn(() => ({
                    sort: jest.fn(() => Promise.resolve([])),
                })),
            })),
        }))
        Model.countDocuments = jest.fn(() => Promise.resolve(0))
        Model.aggregate = jest.fn(() => Promise.resolve([]))
        Model.schema = { obj: {} }
        return Model
    }

    const Schema = function (def, options) {
        this.obj = def
        this.options = options
        this.virtual = jest.fn(() => ({
            get: jest.fn(),
        }))
        this.pre = jest.fn()
        this.index = jest.fn()
    }
    Schema.Types = { Mixed: 'Mixed', ObjectId: 'ObjectId' }

    return {
        default: {
            connect: jest.fn(() =>
                Promise.resolve({ connection: { host: 'mock-host' } })
            ),
            connection: {
                readyState: 1,
                on: jest.fn(),
            },
            Schema,
            model: jest.fn((name) => mockModel(name)),
        },
        Schema,
        model: jest.fn(),
    }
})

jest.unstable_mockModule('../../src/config/database.config.js', () => ({
    default: jest.fn(() => Promise.resolve(null)),
}))

jest.unstable_mockModule('../../src/services/blockchain.service.js', () => ({
    default: {
        _ensureInitialized: jest.fn(),
        anchorCredential: jest.fn(() =>
            Promise.resolve({ txHash: '0xtest123', blockNumber: 1, simulated: true })
        ),
        isCredentialRevoked: jest.fn(() => Promise.resolve(false)),
        getAnchoredHash: jest.fn(() => Promise.resolve(null)),
        revokeCredential: jest.fn(() =>
            Promise.resolve({ success: true, simulated: true })
        ),
        registerDID: jest.fn(() =>
            Promise.resolve({ txHash: null, simulated: true })
        ),
        getIssuerAddress: jest.fn(() => '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266'),
        isConnected: jest.fn(() =>
            Promise.resolve({ connected: true, blockNumber: 100 })
        ),
    },
}))

jest.unstable_mockModule('../../src/config/blockchain.config.js', () => ({
    default: {
        network: { name: 'maticmum', chainId: 80001, rpcUrl: 'http://localhost:8545' },
        issuer: {
            privateKey: '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
        },
        contracts: {},
        gas: {},
    },
}))

// ─── Import AFTER mocks ────────────────────────────────────
// We need to dynamically import the app after setting up mocks
let request

beforeAll(async () => {
    const supertest = await import('supertest')
    request = supertest.default
})

describe('API Integration Tests', () => {
    // ─── HEALTH ENDPOINT ──────────────────────────────────────

    describe('GET /api/health', () => {
        it('returns 200 with health status', async () => {
            const { default: app } = await import('../../src/app.js')

            const response = await request(app).get('/api/health')

            expect(response.status).toBe(200)
            expect(response.body.success).toBe(true)
            expect(response.body.status).toBe('healthy')
            expect(response.body.timestamp).toBeDefined()
        })
    })

    // ─── ROOT ENDPOINT ────────────────────────────────────────

    describe('GET /', () => {
        it('returns API info', async () => {
            const { default: app } = await import('../../src/app.js')

            const response = await request(app).get('/')

            expect(response.status).toBe(200)
            expect(response.body.name).toBe('DIGIPASS Identity Engine')
            expect(response.body.endpoints).toBeDefined()
        })
    })

    // ─── 404 HANDLER ──────────────────────────────────────────

    describe('Unknown routes', () => {
        it('returns 404 for unknown endpoints', async () => {
            const { default: app } = await import('../../src/app.js')

            const response = await request(app).get('/api/nonexistent')

            expect(response.status).toBe(404)
            expect(response.body.success).toBe(false)
        })
    })

    // ─── CREDENTIAL ENDPOINTS ─────────────────────────────────

    describe('POST /api/credentials/issue', () => {
        it('returns 401 when called without authentication', async () => {
            const { default: app } = await import('../../src/app.js')

            const response = await request(app)
                .post('/api/credentials/issue')
                .send({
                    subjectDID: 'did:ethr:maticmum:0xAlice',
                    credentialType: 'DigitalPassCredential',
                    claims: { name: 'Alice' },
                    expiryDate: '2027-12-31T00:00:00Z',
                })

            expect(response.status).toBe(401)
        })
    })

    describe('POST /api/credentials/verify', () => {
        it('returns 400 when credential is missing', async () => {
            const { default: app } = await import('../../src/app.js')

            const response = await request(app)
                .post('/api/credentials/verify')
                .send({})

            expect(response.status).toBe(400)
        })
    })

    // ─── PRESENTATION ENDPOINTS ───────────────────────────────

    describe('POST /api/presentation/challenge', () => {
        it('returns 400 for invalid DID format', async () => {
            const { default: app } = await import('../../src/app.js')

            const response = await request(app)
                .post('/api/presentation/challenge')
                .send({
                    verifierDID: 'not-a-valid-did',
                })

            expect(response.status).toBe(400)
            expect(response.body.success).toBe(false)
        })
    })

    // ─── IDENTITY ENDPOINTS ───────────────────────────────────

    describe('POST /api/identity/create', () => {
        it('returns 400 for invalid role', async () => {
            const { default: app } = await import('../../src/app.js')

            const response = await request(app)
                .post('/api/identity/create')
                .send({
                    role: 'superadmin', // Invalid role
                })

            expect(response.status).toBe(400)
        })
    })
})
