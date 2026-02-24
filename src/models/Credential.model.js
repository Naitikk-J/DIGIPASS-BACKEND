// src/models/Credential.model.js
// Stores issued Verifiable Credentials in MongoDB
// This is the backend's record — the user also holds the VC in their wallet

import mongoose from 'mongoose'

const credentialSchema = new mongoose.Schema(
    {
        credentialId: {
            type: String,
            required: true,
            unique: true,
            index: true,
        },
        issuerDID: {
            type: String,
            required: true,
            index: true,
        },
        subjectDID: {
            type: String,
            required: true,
            index: true,
        },
        credentialType: {
            type: String,
            required: true,
            enum: [
                'DigitalPassCredential',
                'EmploymentCredential',
                'EducationCredential',
                'EventPassCredential',
                'AccessCredential',
            ],
        },
        claims: {
            name: { type: String, required: true },
            passType: String,
            accessLevel: {
                type: String,
                enum: ['basic', 'standard', 'premium', 'admin'],
                default: 'basic',
            },
            organizationId: String,
            // Flexible extra claims
            additionalClaims: mongoose.Schema.Types.Mixed,
        },
        // The signed JWT credential
        credentialJWT: {
            type: String,
        },
        // Full credential object (W3C VC data model)
        credentialDocument: {
            type: mongoose.Schema.Types.Mixed,
        },
        issuanceDate: {
            type: Date,
            default: Date.now,
        },
        expirationDate: {
            type: Date,
            required: true,
        },
        // Blockchain anchoring data
        onChain: {
            txHash: String,
            blockNumber: Number,
            credentialHash: String,
            anchoredAt: Date,
        },
        // Revocation status
        revocation: {
            isRevoked: { type: Boolean, default: false },
            revokedAt: Date,
            revokedBy: String,
            revocationTxHash: String,
            reason: String,
        },
        status: {
            type: String,
            enum: ['active', 'expired', 'revoked', 'suspended'],
            default: 'active',
        },
    },
    {
        timestamps: true,
        toJSON: { virtuals: true },
    }
)

// Virtual: check if expired
credentialSchema.virtual('isExpired').get(function () {
    return this.expirationDate && new Date(this.expirationDate) < new Date()
})

// Pre-save: auto-update status
credentialSchema.pre('save', function (next) {
    if (this.revocation?.isRevoked) {
        this.status = 'revoked'
    } else if (this.isExpired) {
        this.status = 'expired'
    }
    next()
})

// Index for efficient querying
credentialSchema.index({ issuerDID: 1, status: 1 })
credentialSchema.index({ subjectDID: 1, status: 1 })
credentialSchema.index({ credentialType: 1 })

const Credential = mongoose.model('Credential', credentialSchema)

export default Credential
