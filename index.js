import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { MongoClient, ObjectId, ServerApiVersion } from 'mongodb';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import admin from 'firebase-admin';
import { createRequire } from "module";
const require = createRequire(import.meta.url);
// Firebase Admin Setup
const serviceAccountKey = process.env.FIREBASE_SERVICE_ACCOUNT;
let serviceAccount;

if (serviceAccountKey) {
    try {
        serviceAccount = JSON.parse(serviceAccountKey);
    } catch (error) {
        console.error("Error parsing FIREBASE_SERVICE_ACCOUNT:", error);
    }
} else {
    try {
        serviceAccount = require("./public-infrastrure-system-firebase-adminsdk.json");
    } catch (error) {
        console.warn("Firebase service account file not found.");
    }
}

dotenv.config();

if (serviceAccount) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
} else {
    console.warn("Firebase Auth initialized without credentials (might fail in production)");
}

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// MongoDB Connection
const uri = process.env.MONGODB_URI;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

let db;
let dbConnected = false;

async function connectToDatabase() {
    try {
        // Connect the client to the server
        await client.connect();
        // Send a ping to confirm a successful connection
        // await client.db("admin").command({ ping: 1 });

        db = client.db('infrastructure_reporting');
        dbConnected = true;
        console.log("Pinged your deployment. You successfully connected to MongoDB!");


        // Create indexes for better performance
        await db.collection('users').createIndex({ email: 1 }, { unique: true });
        await db.collection('issues').createIndex({ status: 1 });
        await db.collection('issues').createIndex({ citizenId: 1 });

        await seedUsers();

    } catch (error) {
        console.error('❌ MongoDB connection error:', error);
        dbConnected = false;
        console.log("Retrying connection in 5 seconds...");
        setTimeout(connectToDatabase, 5000);
    }
}

const seedUsers = async () => {
    try {
        const staffPassword = await bcrypt.hash('staff123', 10);
        await db.collection('users').updateOne(
            { email: 'staff@gmail.com' },
            {
                $set: {
                    name: 'Default Staff',
                    email: 'staff@gmail.com',
                    password: staffPassword,
                    role: 'staff',
                    createdAt: new Date(),
                    isBlocked: false
                }
            },
            { upsert: true }
        );
        console.log("✅ Seeded Staff User: staff@gmail.com");

        const citizenPassword = await bcrypt.hash('citizen123', 10);
        await db.collection('users').updateOne(
            { email: 'citizen@gmail.com' },
            {
                $set: {
                    name: 'Default Citizen',
                    email: 'citizen@gmail.com',
                    password: citizenPassword,
                    role: 'citizen',
                    createdAt: new Date(),
                    isBlocked: false
                }
            },
            { upsert: true }
        );
        console.log("✅ Seeded Citizen User: citizen@gmail.com");

        const adminPassword = await bcrypt.hash('sonaton123', 10);
        await db.collection('users').updateOne(
            { email: 'sonaton.fl@gmail.com' },
            {
                $set: {
                    name: 'Sonaton Admin',
                    email: 'sonaton.fl@gmail.com',
                    password: adminPassword,
                    role: 'admin',
                    createdAt: new Date(),
                    isBlocked: false
                }
            },
            { upsert: true }
        );
        console.log("✅ Seeded Admin User: sonaton.fl@gmail.com");

    } catch (error) {
        console.error("Error seeding users:", error);
    }
};

connectToDatabase();

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Role-based authorization middleware
const authorizeRole = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Access denied. Insufficient permissions.' });
        }
        next();
    };
};

// ============ AUTHENTICATION ROUTES ============

// Register new user
app.post('/api/auth/register', async (req, res) => {
    try {
        if (!dbConnected) {
            return res.status(503).json({ message: 'Database not connected' });
        }

        const { name, email, password, phone, address, isPremium = false, photo } = req.body;

        // Validate input
        if (!name || !email || !password) {
            return res.status(400).json({ message: 'Name, email, and password are required' });
        }

        // Check if user already exists
        const existingUser = await db.collection('users').findOne({ email });
        if (existingUser) {
            return res.status(409).json({ message: 'User with this email already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user object
        const newUser = {
            name,
            email,
            password: hashedPassword,
            phone: phone || '',
            address: address || '',
            role: 'citizen', // Enforce citizen role for public registration
            isPremium: isPremium,
            isBlocked: false,
            photo: photo || null, // Store photo URL/Base64
            createdAt: new Date(),
            updatedAt: new Date()
        };

        const result = await db.collection('users').insertOne(newUser);

        // Generate JWT token
        const token = jwt.sign(
            {
                userId: result.insertedId.toString(),
                email: newUser.email,
                role: newUser.role,
                isPremium: newUser.isPremium
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(201).json({
            message: 'User registered successfully',
            token,
            user: {
                id: result.insertedId,
                name: newUser.name,
                email: newUser.email,
                role: newUser.role,
                isPremium: newUser.isPremium
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Server error during registration' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        if (!dbConnected) {
            return res.status(503).json({ message: 'Database not connected' });
        }

        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        // Find user
        const user = await db.collection('users').findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Generate JWT token
        const token = jwt.sign(
            {
                userId: user._id.toString(),
                email: user.email,
                role: user.role,
                isPremium: user.isPremium || false
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                role: user.role,
                isPremium: user.isPremium || false,
                isBlocked: user.isBlocked || false,
                phone: user.phone,
                address: user.address
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login' });
    }
});

// Google Login
app.post('/api/auth/google', async (req, res) => {
    try {
        const { token } = req.body;
        if (!token) return res.status(400).json({ message: 'Token required' });

        const decodedToken = await admin.auth().verifyIdToken(token);
        const { email, name, picture, uid } = decodedToken;

        let user = await db.collection('users').findOne({ email });

        if (!user) {
            // Register new citizen
            const newUser = {
                name: name || 'Google User',
                email,
                password: '', // No password for Google users
                role: 'citizen',
                isPremium: false,
                isBlocked: false,
                photo: picture || null,
                googleId: uid,
                createdAt: new Date(),
                updatedAt: new Date()
            };
            const result = await db.collection('users').insertOne(newUser);
            user = { ...newUser, _id: result.insertedId };
        } else {
            // Update googleId if missing
            if (!user.googleId) {
                await db.collection('users').updateOne({ _id: user._id }, { $set: { googleId: uid, photo: picture || user.photo } });
            }
        }

        if (user.isBlocked) {
            return res.status(403).json({ message: 'Account is blocked' });
        }

        const jwtToken = jwt.sign(
            {
                userId: user._id.toString(),
                email: user.email,
                role: user.role,
                isPremium: user.isPremium
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            message: 'Login successful',
            token: jwtToken,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                isPremium: user.isPremium
            }
        });

    } catch (error) {
        console.error('Google Auth Error:', error);
        res.status(401).json({ message: 'Invalid token' });
    }
});

// Get current user profile
app.get('/api/auth/profile', authenticateToken, async (req, res) => {
    try {
        if (!dbConnected) {
            return res.status(503).json({ message: 'Database not connected' });
        }

        const user = await db.collection('users').findOne(
            { _id: new ObjectId(req.user.userId) },
            { projection: { password: 0 } }
        );

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({ user });
    } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update current user profile
app.patch('/api/auth/profile', authenticateToken, async (req, res) => {
    try {
        if (!dbConnected) {
            return res.status(503).json({ message: 'Database not connected' });
        }

        const { name, phone, address } = req.body;
        const updateFields = { updatedAt: new Date() };

        if (name) updateFields.name = name;
        if (phone) updateFields.phone = phone;
        if (address) updateFields.address = address;

        const result = await db.collection('users').updateOne(
            { _id: new ObjectId(req.user.userId) },
            { $set: updateFields }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({ message: 'Profile updated successfully' });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// ============ ISSUE ROUTES ============

// Create new issue (Citizens only)
app.post('/api/issues', authenticateToken, authorizeRole('citizen'), async (req, res) => {
    try {
        if (!dbConnected) {
            return res.status(503).json({ message: 'Database not connected' });
        }

        const { title, description, category, location, photos } = req.body;

        // Check if user is blocked or has reached limit
        const user = await db.collection('users').findOne({ _id: new ObjectId(req.user.userId) });

        if (user?.isBlocked) {
            return res.status(403).json({ message: 'Your account is blocked. You cannot submit issues.' });
        }

        // Check limit for free users
        if (!user?.isPremium && user?.role === 'citizen') {
            const issueCount = await db.collection('issues').countDocuments({ citizenId: new ObjectId(req.user.userId) });
            if (issueCount >= 3) {
                return res.status(403).json({
                    message: 'Free users can only report 3 issues. Please upgrade to Premium for unlimited reporting.',
                    requiresUpgrade: true
                });
            }
        }

        if (!title || !description || !category || !location) {
            return res.status(400).json({ message: 'Title, description, category, and location are required' });
        }

        const newIssue = {
            title,
            description,
            category, // pothole, streetlight, water_leakage, garbage, footpath, other
            location: {
                address: location.address || '',
                latitude: location.latitude || 0,
                longitude: location.longitude || 0
            },
            photos: photos || [],
            citizenId: new ObjectId(req.user.userId),
            citizenName: '', // Will be populated
            citizenEmail: req.user.email,
            isPremiumIssue: req.user.isPremium || false,
            status: 'pending', // pending, assigned, in-progress, resolved, closed
            assignedTo: null,
            assignedStaffName: null,
            priority: req.user.isPremium ? 'high' : 'normal', // high, normal, low
            comments: [],
            statusHistory: [
                {
                    status: 'pending',
                    updatedBy: req.user.email,
                    updatedByRole: 'citizen',
                    timestamp: new Date(),
                    comment: req.user.isPremium ? 'Priority Issue reported by Premium Citizen' : 'Issue reported by citizen'
                }
            ],
            createdAt: new Date(),
            updatedAt: new Date()
        };

        // Get citizen name
        const citizen = await db.collection('users').findOne({ _id: new ObjectId(req.user.userId) });
        if (citizen) {
            newIssue.citizenName = citizen.name;
        }

        const result = await db.collection('issues').insertOne(newIssue);

        res.status(201).json({
            message: 'Issue reported successfully',
            issue: { ...newIssue, _id: result.insertedId }
        });
    } catch (error) {
        console.error('Issue creation error:', error);
        res.status(500).json({ message: 'Server error while creating issue' });
    }
});

// Get all issues (with filtering)
app.get('/api/issues', async (req, res) => {
    try {
        if (!dbConnected) {
            return res.status(503).json({ message: 'Database not connected' });
        }

        const { status, category, priority, citizenId, search, page = 1, limit = 10 } = req.query;
        const filter = {};

        // Apply filters
        if (status) filter.status = status;
        if (category) filter.category = category;
        if (priority) filter.priority = priority;
        if (citizenId) {
            filter.citizenId = new ObjectId(citizenId);
        }

        // Search functionality
        if (search) {
            filter.$or = [
                { title: { $regex: search, $options: 'i' } },
                { description: { $regex: search, $options: 'i' } },
                { category: { $regex: search, $options: 'i' } },
                { 'location.address': { $regex: search, $options: 'i' } }
            ];
        }

        const pageNum = parseInt(page);
        const limitNum = parseInt(limit);
        const skip = (pageNum - 1) * limitNum;

        const totalIssues = await db.collection('issues').countDocuments(filter);
        const totalPages = Math.ceil(totalIssues / limitNum);

        const issues = await db.collection('issues')
            .find(filter)
            .sort({ isPremiumIssue: -1, upvotes: -1, createdAt: -1 })
            .skip(skip)
            .limit(limitNum)
            .toArray();

        res.json({
            issues,
            pagination: {
                totalIssues,
                totalPages,
                currentPage: pageNum,
                limit: limitNum
            }
        });
    } catch (error) {
        console.error('Issue fetch error:', error);
        res.status(500).json({ message: 'Server error while fetching issues' });
    }
});

// Get single issue by ID
app.get('/api/issues/:id', async (req, res) => {
    try {
        if (!dbConnected) {
            return res.status(503).json({ message: 'Database not connected' });
        }

        const issue = await db.collection('issues').findOne({ _id: new ObjectId(req.params.id) });

        if (!issue) {
            return res.status(404).json({ message: 'Issue not found' });
        }

        res.json({ issue });
    } catch (error) {
        console.error('Issue fetch error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Upvote an issue
app.put('/api/issues/:id/upvote', authenticateToken, async (req, res) => {
    try {
        if (!dbConnected) {
            return res.status(503).json({ message: 'Database not connected' });
        }

        // Check if user is blocked
        const user = await db.collection('users').findOne({ _id: new ObjectId(req.user.userId) });
        if (user?.isBlocked) {
            return res.status(403).json({ message: 'Your account is blocked. You cannot upvote.' });
        }

        const issueId = req.params.id;
        const userId = req.user.userId;

        const issue = await db.collection('issues').findOne({ _id: new ObjectId(issueId) });

        if (!issue) {
            return res.status(404).json({ message: 'Issue not found' });
        }

        // Users cannot upvote their own issue
        if (issue.citizenId.toString() === userId) {
            return res.status(403).json({ message: 'You cannot upvote your own issue' });
        }

        // Check if already upvoted
        if (issue.upvotedBy && issue.upvotedBy.includes(userId)) {
            return res.status(400).json({ message: 'You have already upvoted this issue' });
        }

        const result = await db.collection('issues').updateOne(
            { _id: new ObjectId(issueId) },
            {
                $inc: { upvotes: 1 },
                $push: { upvotedBy: userId },
                $set: { updatedAt: new Date() }
            }
        );

        // Create timeline entry for Boost
        await db.collection('issues').updateOne(
            { _id: new ObjectId(issueId) },
            {
                $push: {
                    statusHistory: {
                        status: 'boosted',
                        updatedBy: req.user.email,
                        updatedByRole: req.user.role,
                        timestamp: new Date(),
                        comment: 'Issue boosted! Priority increased.'
                    }
                }
            }
        );

        res.json({ message: 'Upvoted successfully', upvotes: (issue.upvotes || 0) + 1 });

    } catch (error) {
        console.error('Upvote error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});



// Subscribe / Payment Endpoint (Mock)
app.post('/api/payment/subscribe', authenticateToken, async (req, res) => {
    try {
        if (!dbConnected) {
            return res.status(503).json({ message: 'Database not connected' });
        }

        // In a real app, verify Stripe/Payment gateway here
        // For now, we instantly upgrade the user
        const { amount } = req.body;

        if (amount < 1000) {
            return res.status(400).json({ message: 'Invalid amount. Subscription costs 1000tk.' });
        }

        await db.collection('users').updateOne(
            { _id: new ObjectId(req.user.userId) },
            {
                $set: {
                    isPremium: true,
                    updatedAt: new Date()
                }
            }
        );

        res.json({ message: 'Subscription successful! You are now a Premium user.' });

    } catch (error) {
        console.error('Payment error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Assign issue to staff (Admin only)
app.patch('/api/issues/:id/assign', authenticateToken, authorizeRole('admin'), async (req, res) => {
    try {
        if (!dbConnected) {
            return res.status(503).json({ message: 'Database not connected' });
        }

        const { staffId } = req.body;

        if (!staffId) {
            return res.status(400).json({ message: 'Staff ID is required' });
        }

        // Get staff details
        const staff = await db.collection('users').findOne({
            _id: new ObjectId(staffId),
            role: 'staff'
        });

        if (!staff) {
            return res.status(404).json({ message: 'Staff member not found' });
        }

        const result = await db.collection('issues').updateOne(
            { _id: new ObjectId(req.params.id) },
            {
                $set: {
                    assignedTo: new ObjectId(staffId),
                    assignedStaffName: staff.name,
                    status: 'assigned',
                    updatedAt: new Date()
                },
                $push: {
                    statusHistory: {
                        status: 'assigned',
                        updatedBy: req.user.email,
                        updatedByRole: req.user.role,
                        timestamp: new Date(),
                        comment: `Issue assigned to Staff: ${staff.name}`
                    }
                }
            }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ message: 'Issue not found' });
        }

        res.json({ message: 'Issue assigned successfully' });
    } catch (error) {
        console.error('Issue assignment error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update issue status (Staff and Admin)
app.patch('/api/issues/:id/status', authenticateToken, authorizeRole('staff', 'admin'), async (req, res) => {
    try {
        if (!dbConnected) {
            return res.status(503).json({ message: 'Database not connected' });
        }

        const { status, comment } = req.body;
        const validStatuses = ['pending', 'assigned', 'in-progress', 'working', 'resolved', 'closed', 'rejected'];
        if (!validStatuses.includes(status)) {
            return res.status(400).json({ message: 'Invalid status' });
        }

        const issue = await db.collection('issues').findOne({ _id: new ObjectId(req.params.id) });

        if (!issue) {
            return res.status(404).json({ message: 'Issue not found' });
        }

        // Staff can only update issues assigned to them
        if (req.user.role === 'staff' && (!issue.assignedTo || issue.assignedTo.toString() !== req.user.userId)) {
            return res.status(403).json({ message: 'You can only update issues assigned to you' });
        }

        // If status is changing to 'rejected', ensure it was pending
        if (status === 'rejected' && issue.status !== 'pending') {
            return res.status(400).json({ message: 'Can only reject pending issues' });
        }

        const updateDoc = {
            $set: { status, updatedAt: new Date() },
            $push: {
                statusHistory: {
                    status,
                    changedBy: req.user.userId,
                    changedByName: req.user.name, // Ideally fetch name
                    comment: comment || `Status updated to ${status}`,
                    date: new Date()
                }
            }
        };

        await db.collection('issues').updateOne(
            { _id: new ObjectId(req.params.id) },
            updateDoc
        );

        res.json({ message: 'Issue status updated' });
    } catch (error) {
        console.error('Status update error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Assign Staff to Issue
app.put('/api/issues/:id/assign', authenticateToken, authorizeRole('admin'), async (req, res) => {
    try {
        if (!dbConnected) return res.status(503).json({ message: 'Database not connected' });

        const { staffId } = req.body;
        if (!staffId) return res.status(400).json({ message: 'Staff ID is required' });

        const staff = await db.collection('users').findOne({ _id: new ObjectId(staffId), role: 'staff' });
        if (!staff) return res.status(404).json({ message: 'Staff member not found' });

        const issue = await db.collection('issues').findOne({ _id: new ObjectId(req.params.id) });
        if (!issue) return res.status(404).json({ message: 'Issue not found' });

        // Check if already assigned
        if (issue.assignedTo) {
            return res.status(400).json({ message: 'Issue is already assigned' });
        }

        const updateDoc = {
            $set: {
                assignedTo: staffId.toString(),
                assignedStaffName: staff.name,
                status: 'assigned', // Workflow: Pending -> Assigned -> In Progress
                updatedAt: new Date()
            },
            $push: {
                statusHistory: {
                    status: 'assigned',
                    changedBy: req.user.userId,
                    changedByName: req.user.name,
                    comment: `Assigned to staff: ${staff.name}`,
                    date: new Date()
                }
            }
        };

        await db.collection('issues').updateOne(
            { _id: new ObjectId(req.params.id) },
            updateDoc
        );

        res.json({ message: `Issue assigned to ${staff.name}` });
    } catch (error) {
        console.error('Assign issue error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Reject Issue
app.put('/api/issues/:id/reject', authenticateToken, authorizeRole('admin'), async (req, res) => {
    try {
        if (!dbConnected) return res.status(503).json({ message: 'Database not connected' });

        const issue = await db.collection('issues').findOne({ _id: new ObjectId(req.params.id) });
        if (!issue) return res.status(404).json({ message: 'Issue not found' });

        if (issue.status !== 'pending') {
            return res.status(400).json({ message: 'Only pending issues can be rejected' });
        }

        const updateDoc = {
            $set: { status: 'rejected', updatedAt: new Date() },
            $push: {
                statusHistory: {
                    status: 'rejected',
                    changedBy: req.user.userId,
                    changedByName: req.user.name,
                    comment: 'Issue rejected by admin',
                    date: new Date()
                }
            }
        };

        await db.collection('issues').updateOne(
            { _id: new ObjectId(req.params.id) },
            updateDoc
        );

        res.json({ message: 'Issue rejected successfully' });
    } catch (error) {
        console.error('Reject issue error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Add comment to issue
app.post('/api/issues/:id/comments', authenticateToken, async (req, res) => {
    try {
        if (!dbConnected) {
            return res.status(503).json({ message: 'Database not connected' });
        }

        const { comment } = req.body;

        if (!comment) {
            return res.status(400).json({ message: 'Comment is required' });
        }

        const user = await db.collection('users').findOne({ _id: new ObjectId(req.user.userId) });

        const newComment = {
            text: comment,
            authorId: new ObjectId(req.user.userId),
            authorName: user?.name || 'Unknown',
            authorRole: req.user.role,
            timestamp: new Date()
        };

        const result = await db.collection('issues').updateOne(
            { _id: new ObjectId(req.params.id) },
            {
                $push: { comments: newComment },
                $set: { updatedAt: new Date() }
            }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ message: 'Issue not found' });
        }

        res.json({ message: 'Comment added successfully', comment: newComment });
    } catch (error) {
        console.error('Comment error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});



// Update issue details (Citizen only, if pending)
app.put('/api/issues/:id', authenticateToken, authorizeRole('citizen'), async (req, res) => {
    try {
        if (!dbConnected) {
            return res.status(503).json({ message: 'Database not connected' });
        }

        const { title, description, category, location, photos } = req.body;

        const issue = await db.collection('issues').findOne({ _id: new ObjectId(req.params.id) });

        if (!issue) {
            return res.status(404).json({ message: 'Issue not found' });
        }

        // Check if user is blocked
        const user = await db.collection('users').findOne({ _id: new ObjectId(req.user.userId) });
        if (user?.isBlocked) {
            return res.status(403).json({ message: 'Your account is blocked. You cannot edit issues.' });
        }

        // Verify ownership
        if (issue.citizenId.toString() !== req.user.userId) {
            return res.status(403).json({ message: 'You can only edit your own issues' });
        }

        // Verify status
        if (issue.status !== 'pending') {
            return res.status(400).json({ message: 'You can only edit pending issues' });
        }

        const updateFields = {
            updatedAt: new Date()
        };

        if (title) updateFields.title = title;
        if (description) updateFields.description = description;
        if (category) updateFields.category = category;
        if (location) updateFields.location = location;
        if (photos) updateFields.photos = photos;

        await db.collection('issues').updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: updateFields }
        );

        res.json({ message: 'Issue updated successfully' });
    } catch (error) {
        console.error('Issue update error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Delete issue
app.delete('/api/issues/:id', authenticateToken, async (req, res) => {
    try {
        if (!dbConnected) {
            return res.status(503).json({ message: 'Database not connected' });
        }

        const issue = await db.collection('issues').findOne({ _id: new ObjectId(req.params.id) });

        if (!issue) {
            return res.status(404).json({ message: 'Issue not found' });
        }

        // Check permissions
        const isAdmin = req.user.role === 'admin';
        const isOwner = issue.citizenId.toString() === req.user.userId;

        if (!isAdmin && !isOwner) {
            return res.status(403).json({ message: 'Access denied' });
        }

        // Check if blocked (for Citizen owner)
        if (isOwner && !isAdmin) {
            const currentUser = await db.collection('users').findOne({ _id: new ObjectId(req.user.userId) });
            if (currentUser?.isBlocked) {
                return res.status(403).json({ message: 'Your account is blocked.' });
            }
        }

        // Citizens can only delete pending issues
        if (isOwner && !isAdmin && issue.status !== 'pending') {
            return res.status(400).json({ message: 'You can only delete pending issues' });
        }

        const result = await db.collection('issues').deleteOne({ _id: new ObjectId(req.params.id) });

        res.json({ message: 'Issue deleted successfully' });
    } catch (error) {
        console.error('Delete error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// ============ USER MANAGEMENT ROUTES (Admin only) ============

// Get all users
app.get('/api/users', authenticateToken, authorizeRole('admin'), async (req, res) => {
    try {
        if (!dbConnected) {
            return res.status(503).json({ message: 'Database not connected' });
        }

        const { role } = req.query;
        const filter = {};

        if (role) filter.role = role;

        const users = await db.collection('users')
            .find(filter, { projection: { password: 0 } })
            .sort({ createdAt: -1 })
            .toArray();

        res.json({ users });
    } catch (error) {
        console.error('Users fetch error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Create new staff member (Admin only)
app.post('/api/staff', authenticateToken, authorizeRole('admin'), async (req, res) => {
    try {
        if (!dbConnected) return res.status(503).json({ message: 'Database not connected' });

        const { name, email, password, phone, address } = req.body;

        // 1. Create user in Firebase Authentication
        let firebaseUser;
        try {
            firebaseUser = await admin.auth().createUser({
                email,
                password,
                displayName: name,
            });
        } catch (firebaseError) {
            console.error('Firebase creation error:', firebaseError);
            return res.status(400).json({ message: 'Error creating user in Firebase: ' + firebaseError.message });
        }

        // 2. Create user in MongoDB
        const newUser = {
            name,
            email,
            role: 'staff', // Enforce staff role
            phone,
            address,
            firebaseUid: firebaseUser.uid,
            isPremium: false,
            isBlocked: false,
            createdAt: new Date()
        };

        const result = await db.collection('users').insertOne(newUser);

        res.status(201).json({ message: 'Staff created successfully', userId: result.insertedId });
    } catch (error) {
        console.error('Create staff error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Update user role, premium status, or blocked status (Admin only)
app.patch('/api/users/:id', authenticateToken, authorizeRole('admin'), async (req, res) => {
    try {
        if (!dbConnected) {
            return res.status(503).json({ message: 'Database not connected' });
        }

        const { role, isPremium, isBlocked } = req.body;
        const updateFields = { updatedAt: new Date() };

        if (role) updateFields.role = role;
        if (isPremium !== undefined) updateFields.isPremium = isPremium;
        if (isBlocked !== undefined) updateFields.isBlocked = isBlocked;

        const result = await db.collection('users').updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: updateFields }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({ message: 'User updated successfully' });
    } catch (error) {
        console.error('User update error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Block/Unblock user (Admin only)
app.patch('/api/users/:id/block', authenticateToken, authorizeRole('admin'), async (req, res) => {
    try {
        if (!dbConnected) {
            return res.status(503).json({ message: 'Database not connected' });
        }

        const { isBlocked } = req.body;

        if (typeof isBlocked !== 'boolean') {
            return res.status(400).json({ message: 'isBlocked must be a boolean' });
        }

        const result = await db.collection('users').updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { isBlocked: isBlocked, updatedAt: new Date() } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json({ message: `User ${isBlocked ? 'blocked' : 'unblocked'} successfully` });
    } catch (error) {
        console.error('Block/unblock user error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Delete user (Admin only)
app.delete('/api/users/:id', authenticateToken, authorizeRole('admin'), async (req, res) => {
    try {
        if (!dbConnected) return res.status(503).json({ message: 'Database not connected' });

        const result = await db.collection('users').deleteOne({ _id: new ObjectId(req.params.id) });
        if (result.deletedCount === 0) return res.status(404).json({ message: 'User not found' });

        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// ============ DASHBOARD STATS ============

// Get dashboard statistics
app.get('/api/stats', authenticateToken, async (req, res) => {
    try {
        if (!dbConnected) {
            return res.status(503).json({ message: 'Database not connected' });
        }

        const filter = {};
        if (req.user.role === 'citizen') {
            filter.citizenId = new ObjectId(req.user.userId);
        }

        const totalIssues = await db.collection('issues').countDocuments(filter);
        const pendingIssues = await db.collection('issues').countDocuments({ ...filter, status: 'pending' });
        const inProgressIssues = await db.collection('issues').countDocuments({ ...filter, status: 'in-progress' });
        const resolvedIssues = await db.collection('issues').countDocuments({ ...filter, status: 'resolved' });
        const closedIssues = await db.collection('issues').countDocuments({ ...filter, status: 'closed' });

        let stats = {
            issues: {
                total: totalIssues,
                pending: pendingIssues,
                inProgress: inProgressIssues,
                resolved: resolvedIssues,
                closed: closedIssues
            },
            totalPayments: req.user.isPremium ? 1000 : 0
        };

        if (req.user.role === 'staff') {
            // Staff sees stats for their assigned issues
            const staffId = req.user.userId;
            const totalAssigned = await db.collection('issues').countDocuments({ assignedTo: staffId });
            const workingIssues = await db.collection('issues').countDocuments({ assignedTo: staffId, status: 'working' });
            const inProgressIssues = await db.collection('issues').countDocuments({ assignedTo: staffId, status: 'in-progress' });
            const resolvedIssues = await db.collection('issues').countDocuments({ assignedTo: staffId, status: 'resolved' });

            // Today's tasks (updated or assigned today)
            const startOfDay = new Date();
            startOfDay.setHours(0, 0, 0, 0);
            const todaysTasks = await db.collection('issues').countDocuments({
                assignedTo: staffId,
                updatedAt: { $gte: startOfDay }
            });

            stats.issues = {
                total: totalAssigned,
                working: workingIssues,
                inProgress: inProgressIssues,
                resolved: resolvedIssues,
                today: todaysTasks
            };
        } else if (req.user.role === 'admin') {
            const totalUsers = await db.collection('users').countDocuments();
            const premiumUsers = await db.collection('users').countDocuments({ isPremium: true });
            const staffCount = await db.collection('users').countDocuments({ role: 'staff' });

            // Rejected
            const rejectedIssues = await db.collection('issues').countDocuments({ status: 'rejected' });

            // Total Payments (Sum of subscriptions) - simplistic
            // In real app, aggregate payments collection. Here we count premium users * 1000
            const totalRevenue = premiumUsers * 1000;

            // Issue breakdown
            const categoryStats = await db.collection('issues').aggregate([
                { $group: { _id: '$category', count: { $sum: 1 } } }
            ]).toArray();

            stats.issues.rejected = rejectedIssues;
            stats.users = {
                total: totalUsers,
                premium: premiumUsers,
                staff: staffCount
            };
            stats.revenue = totalRevenue;
            stats.categoryBreakdown = categoryStats;
        }

        res.json(stats);
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get payments (Admin only)
app.get('/api/payments', authenticateToken, authorizeRole('admin'), async (req, res) => {
    try {
        if (!dbConnected) {
            return res.status(503).json({ message: 'Database not connected' });
        }

        // Mock payment data since we don't have a real payment gateway integrated yet
        // In a real app, this would query a 'payments' collection
        const payments = [
            { id: 1, user: 'John Doe', amount: 50, type: 'Subscription', date: new Date(), status: 'Completed' },
            { id: 2, user: 'Jane Smith', amount: 10, type: 'Boost', date: new Date(Date.now() - 86400000), status: 'Completed' },
        ];

        res.json({ payments });
    } catch (error) {
        console.error('Payments error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Contact Form Submission
app.post('/api/contact', async (req, res) => {
    try {
        if (!dbConnected) {
            return res.status(503).json({ message: 'Database not connected' });
        }

        const { name, email, subject, message } = req.body;

        if (!name || !email || !message) {
            return res.status(400).json({ message: 'Name, email, and message are required' });
        }

        const newMessage = {
            name,
            email,
            subject,
            message,
            status: 'unread',
            createdAt: new Date()
        };

        await db.collection('messages').insertOne(newMessage);

        res.status(201).json({ message: 'Message sent successfully' });
    } catch (error) {
        console.error('Contact error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'OK',
        database: dbConnected ? 'Connected' : 'Disconnected',
        timestamp: new Date()
    });
});

// Root route
app.get('/', (req, res) => {
    res.json({
        message: 'Public Infrastructure Issue Reporting System API',
        version: '1.0.0',
        status: 'Running'
    });
});

// Start server
// Start server only if not running on Vercel
if (process.env.VERCEL !== '1') {
    app.listen(PORT, () => {
        console.log(`🚀 Server running on port ${PORT}`);
        console.log(`📍 API: http://localhost:${PORT}`);
    });
}

export default app;

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('\n🛑 Shutting down gracefully...');
    await client.close();
    process.exit(0);
});
