import mongoose from 'mongoose';
import AuditLog from '../models/AuditLog.js';
import dotenv from 'dotenv';

import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const envPath = path.join(__dirname, '../.env');
console.log('Loading .env from:', envPath);
const result = dotenv.config({ path: envPath });
if (result.error) {
    console.error('Error loading .env:', result.error);
}

console.log('MONGODB_URI:', process.env.MONGODB_URI);

const checkLogs = async () => {
    try {
        const uri = process.env.MONGODB_URI || 'mongodb://localhost:27017/secure-messaging';
        await mongoose.connect(uri);
        console.log('Connected to MongoDB');

        const logs = await AuditLog.find().sort({ timestamp: -1 }).limit(20);

        console.log('\n--- Recent Audit Logs ---');
        if (logs.length === 0) {
            console.log('No logs found.');
        } else {
            logs.forEach(log => {
                console.log(`[${log.timestamp.toISOString()}] [${log.eventType}] [${log.status}] User: ${log.username || log.userId || 'Anon'} - ${JSON.stringify(log.details)}`);
            });
        }
        console.log('-------------------------\n');

        await mongoose.disconnect();
    } catch (error) {
        console.error('Error checking logs:', error);
    }
};

checkLogs();
