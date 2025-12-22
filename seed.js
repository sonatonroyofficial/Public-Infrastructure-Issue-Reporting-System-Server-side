import { MongoClient } from 'mongodb';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, '.env') });

const uri = process.env.MONGODB_URI;
if (!uri) {
    console.error('❌ MONGODB_URI not found in .env file');
    process.exit(1);
}

const client = new MongoClient(uri);

const users = [
    {
        name: 'Admin User',
        email: 'admin@test.com',
        password: 'admin123',
        role: 'admin',
        isPremium: true
    },
    {
        name: 'Staff User',
        email: 'staff@test.com',
        password: 'staff123',
        role: 'staff',
        isPremium: false
    },
    {
        name: 'Citizen User',
        email: 'citizen@test.com',
        password: 'citizen123',
        role: 'citizen',
        isPremium: false
    }
];

async function seedUsers() {
    try {
        await client.connect();
        console.log('✅ Connected to MongoDB');

        const db = client.db('infrastructure_reporting');

        // Clear existing users with these emails to avoid duplicates during re-seeding
        // or just rely on the unique index and try-catch

        for (const user of users) {
            const existingUser = await db.collection('users').findOne({ email: user.email });

            if (existingUser) {
                console.log(`⚠️ User ${user.email} already exists. Skipping...`);
                continue;
            }

            const hashedPassword = await bcrypt.hash(user.password, 10);

            const newUser = {
                ...user,
                password: hashedPassword,
                createdAt: new Date(),
                updatedAt: new Date()
            };

            await db.collection('users').insertOne(newUser);
            console.log(`✅ Created user: ${user.email} (${user.role})`);
        }

        console.log('🌱 Seeding completed successfully');

    } catch (error) {
        console.error('❌ Seeding error:', error);
    } finally {
        await client.close();
    }
}

seedUsers();
