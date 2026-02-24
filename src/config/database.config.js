// src/config/database.config.js
// MongoDB connection configuration using Mongoose
import mongoose from 'mongoose'

const connectDB = async () => {
    try {
        const conn = await mongoose.connect(process.env.MONGODB_URI, {
            // Mongoose 8 defaults are good, but we set these explicitly for clarity
            maxPoolSize: 10,
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
        })

        console.log(`✅ MongoDB connected: ${conn.connection.host}`)

        // Handle connection events
        mongoose.connection.on('error', (err) => {
            console.error('❌ MongoDB connection error:', err)
        })

        mongoose.connection.on('disconnected', () => {
            console.warn('⚠️  MongoDB disconnected. Attempting reconnection...')
        })

        return conn
    } catch (error) {
        console.error('❌ MongoDB connection failed:', error.message)
        console.warn('⚠️  Server will start without database — some features will be unavailable')
        return null
    }
}

export default connectDB
