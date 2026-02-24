// src/config/database.config.js
// MongoDB connection configuration using Mongoose
import mongoose from 'mongoose'

const connectDB = async () => {
    try {
        if (!process.env.MONGODB_URI) {
            throw new Error('MONGODB_URI is not defined in environment variables');
        }

        const conn = await mongoose.connect(process.env.MONGODB_URI, {
            serverSelectionTimeoutMS: 10000, // Wait up to 10s for connection
            socketTimeoutMS: 45000,
        });

        console.log(`✅ MongoDB connected: ${conn.connection.host}`);
        return conn;
    } catch (error) {
        console.error('❌ MongoDB connection failed:', error.message);
        throw error; // Rethrow to prevent app from starting in broken state
    }
};

export default connectDB
