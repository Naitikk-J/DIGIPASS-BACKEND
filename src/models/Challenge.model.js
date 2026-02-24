// src/models/Challenge.model.js
import mongoose from 'mongoose'

const challengeSchema = new mongoose.Schema({
    id: {
        type: String,
        required: true,
        unique: true,
        index: true,
    },
    nonce: {
        type: String,
        required: true,
    },
    verifierDID: {
        type: String,
        required: true,
    },
    requestedCredentialTypes: [String],
    expiresAt: {
        type: Date,
        required: true,
        index: { expires: '5m' }, // TTL index
    },
}, {
    timestamps: true,
})

const Challenge = mongoose.model('Challenge', challengeSchema)
export default Challenge
