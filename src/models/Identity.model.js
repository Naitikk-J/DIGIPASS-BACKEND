// src/models/Identity.model.js
// Stores DID (Decentralized Identifier) records in MongoDB
// Each identity represents a user or issuer in the system

import mongoose from 'mongoose'

const identitySchema = new mongoose.Schema(
    {
        did: {
            type: String,
            required: true,
            unique: true,
            index: true,
            validate: {
                validator: (v) => /^did:ethr:/.test(v),
                message: 'DID must follow the did:ethr format',
            },
        },
        address: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
        },
        publicKey: {
            type: String,
            default: '',
        },
        didDocument: {
            type: mongoose.Schema.Types.Mixed,
            default: null,
        },
        role: {
            type: String,
            enum: ['holder', 'issuer', 'verifier'],
            default: 'holder',
        },
        isActive: {
            type: Boolean,
            default: true,
        },
        metadata: {
            name: String,
            organization: String,
            email: String,
        },
        onChain: {
            txHash: String,
            blockNumber: Number,
            registeredAt: Date,
        },
    },
    {
        timestamps: true,
        toJSON: { virtuals: true },
    }
)

// Virtual: credential count
identitySchema.virtual('credentials', {
    ref: 'Credential',
    localField: 'did',
    foreignField: 'subjectDID',
})

const Identity = mongoose.model('Identity', identitySchema)

export default Identity
