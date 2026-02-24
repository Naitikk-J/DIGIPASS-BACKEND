// src/middleware/validate.middleware.js
// Request validation middleware using Zod schemas.
// Validates req.body, req.params, or req.query.

import { z } from 'zod'

/**
 * Factory function — takes a Zod schema and returns validation middleware.
 *
 * Usage:
 *   router.post('/issue', validate(issueCredentialSchema), handler)
 */
export function validate(schema, source = 'body') {
    return (req, res, next) => {
        try {
            const data = req[source]
            const parsed = schema.parse(data)
            req[source] = parsed // Replace with parsed/cleaned data
            next()
        } catch (error) {
            if (error instanceof z.ZodError) {
                return res.status(400).json({
                    success: false,
                    error: 'Validation failed',
                    details: error.errors.map((e) => ({
                        field: e.path.join('.'),
                        message: e.message,
                    })),
                })
            }
            next(error)
        }
    }
}

// ─── Validation Schemas ─────────────────────────────────────────────

export const issueCredentialSchema = z.object({
    subjectDID: z
        .string()
        .regex(/^did:ethr:/, 'Must be a valid did:ethr DID'),
    credentialType: z.enum([
        'DigitalPassCredential',
        'EmploymentCredential',
        'EducationCredential',
        'EventPassCredential',
        'AccessCredential',
    ]),
    claims: z.object({
        name: z.string().min(1, 'Name is required'),
        passType: z.string().optional(),
        accessLevel: z.enum(['basic', 'standard', 'premium', 'admin']).optional(),
        organizationId: z.string().optional(),
    }),
    expiryDate: z.string().refine((d) => new Date(d) > new Date(), {
        message: 'Expiry date must be in the future',
    }),
})

export const createDIDSchema = z.object({
    role: z.enum(['holder', 'issuer', 'verifier']).optional(),
    metadata: z
        .object({
            name: z.string().optional(),
            organization: z.string().optional(),
            email: z.string().email().optional(),
        })
        .optional(),
})

export const registerIssuerSchema = z.object({
    organizationName: z.string().min(1, 'Organization name is required'),
    name: z.string().optional(),
    email: z.string().email('Valid email is required'),
})

export const generateChallengeSchema = z.object({
    verifierDID: z
        .string()
        .regex(/^did:ethr:/, 'Must be a valid did:ethr DID'),
    requestedCredentialTypes: z.array(z.string()).optional(),
})

export const createPresentationSchema = z.object({
    holderDID: z.string().regex(/^did:ethr:/, 'Must be a valid did:ethr DID'),
    credentials: z.array(z.any()).min(1, 'At least one credential is required'),
    challengeId: z.string().uuid(),
    nonce: z.string().uuid(),
    holderSignature: z.string().min(1, 'Signature is required'),
})

export const verifyPresentationSchema = z.object({
    presentation: z.object({
        holder: z.string(),
        verifiableCredential: z.any(),
        proof: z.object({
            challenge: z.string(),
            domain: z.string(),
            signature: z.string(),
        }).passthrough(),
    }).passthrough(),
    challengeId: z.string().uuid(),
})

export const connectWalletSchema = z.object({
    address: z
        .string()
        .regex(/^0x[a-fA-F0-9]{40}$/, 'Must be a valid Ethereum address'),
    signature: z
        .string()
        .min(1, 'Wallet signature is required'),
    message: z
        .string()
        .min(1, 'The signed message is required'),
})
