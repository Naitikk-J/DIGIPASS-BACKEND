// src/app.js
// Main application entry point — Express server with all middleware and routes.

import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import helmet from 'helmet'
import morgan from 'morgan'
import rateLimit from 'express-rate-limit'

// Config
import connectDB from './config/database.config.js'

// Routes
import healthRoutes from './routes/health.routes.js'
import identityRoutes from './routes/identity.routes.js'
import credentialRoutes from './routes/credential.routes.js'
import presentationRoutes from './routes/presentation.routes.js'
import issuerRoutes from './routes/issuer.routes.js'

const app = express()
const PORT = process.env.PORT || 5000

// ─── Global Middleware ──────────────────────────────────────────

// Security headers
app.use(helmet())

// CORS configuration
app.use(
    cors({
        origin: process.env.FRONTEND_URL || 'http://localhost:8080',
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
        allowedHeaders: ['Content-Type', 'Authorization'],
        credentials: true,
    })
)

// Body parsing
app.use(express.json({ limit: '10mb' })) // VCs can be large
app.use(express.urlencoded({ extended: true }))

// Request logging
if (process.env.NODE_ENV !== 'test') {
    app.use(morgan('dev'))
}

// Rate limiting
const limiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
    max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
    message: {
        success: false,
        error: 'Too many requests — please try again later',
    },
    standardHeaders: true,
    legacyHeaders: false,
})
app.use('/api/', limiter)

// ─── API Routes ────────────────────────────────────────────────

app.use('/api/health', healthRoutes)
app.use('/api/identity', identityRoutes)
app.use('/api/credentials', credentialRoutes)
app.use('/api/presentation', presentationRoutes)
app.use('/api/issuer', issuerRoutes)

// Root route
app.get('/', (_req, res) => {
    res.json({
        name: 'DIGIPASS Identity Engine',
        version: '1.0.0',
        description:
            'Blockchain-backed digital pass & identity system',
        endpoints: {
            health: '/api/health',
            identity: '/api/identity',
            credentials: '/api/credentials',
            presentation: '/api/presentation',
            issuer: '/api/issuer',
        },
        docs: 'See README.md for API documentation',
    })
})

// ─── Error Handling ────────────────────────────────────────────

// 404 handler
app.use((_req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found',
    })
})

// Global error handler
app.use((err, _req, res, _next) => {
    console.error('Unhandled error:', err)
    res.status(err.status || 500).json({
        success: false,
        error:
            process.env.NODE_ENV === 'production'
                ? 'Internal server error'
                : err.message,
        ...(process.env.NODE_ENV !== 'production' && { stack: err.stack }),
    })
})

// ─── Startup ──────────────────────────────────────────────────

const startServer = async () => {
    try {
        // Connect to MongoDB
        await connectDB()

        app.listen(PORT, () => {
            console.log(`
╔══════════════════════════════════════════════════════╗
║                                                      ║
║   🔐 DIGIPASS Identity Engine                        ║
║   ───────────────────────────                        ║
║   Server:     http://localhost:${PORT}                 ║
║   Mode:       ${process.env.NODE_ENV || 'development'}                      ║
║   Network:    ${process.env.NETWORK_NAME || 'maticmum'}                        ║
║                                                      ║
║   API Routes:                                        ║
║     /api/health          — System health             ║
║     /api/identity        — DID management            ║
║     /api/credentials     — Credential lifecycle      ║
║     /api/presentation    — QR verification flow      ║
║     /api/issuer          — Issuer dashboard          ║
║                                                      ║
╚══════════════════════════════════════════════════════╝
      `)
        })
    } catch (error) {
        console.error('❌ Failed to start server:', error)
        process.exit(1)
    }
}

startServer()

// Export for testing
export default app
