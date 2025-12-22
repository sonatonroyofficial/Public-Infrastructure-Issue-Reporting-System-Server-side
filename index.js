import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { MongoClient, ObjectId, ServerApiVersion } from 'mongodb';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

dotenv.config();

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
        await client.db("admin").command({ ping: 1 });

        db = client.db('infrastructure_reporting');
        dbConnected = true;
        console.log("Pinged your deployment. You successfully connected to MongoDB!");

        // Create indexes for better performance
        await db.collection('users').createIndex({ email: 1 }, { unique: true });
        await db.collection('issues').createIndex({ status: 1 });
        await db.collection('issues').createIndex({ citizenId: 1 });

    } catch (error) {
        console.error('❌ MongoDB connection error:', error);
        dbConnected = false;
    }
}

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

        const { name, email, password, phone, address, role = 'citizen', isPremium = false } = req.body;

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
            role, // citizen, staff, admin
            isPremium: role === 'citizen' ? isPremium : false,
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
                isPremium: user.isPremium || false,
                phone: user.phone,
                address: user.address
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login' });
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

        const { status, category, priority, citizenId, search } = req.query;
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

        const issues = await db.collection('issues')
            .find(filter)
            .sort({ isPremiumIssue: -1, upvotes: -1, createdAt: -1 })
            .toArray();

        res.json({ issues });
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
        const validStatuses = ['pending', 'assigned', 'in-progress', 'resolved', 'closed', 'rejected'];

        if (!status || !validStatuses.includes(status)) {
            return res.status(400).json({ message: 'Valid status is required' });
        }

        const issue = await db.collection('issues').findOne({ _id: new ObjectId(req.params.id) });

        if (!issue) {
            return res.status(404).json({ message: 'Issue not found' });
        }

        // Staff can only update issues assigned to them
        if (req.user.role === 'staff' && (!issue.assignedTo || issue.assignedTo.toString() !== req.user.userId)) {
            return res.status(403).json({ message: 'You can only update issues assigned to you' });
        }

        const result = await db.collection('issues').updateOne(
            { _id: new ObjectId(req.params.id) },
            {
                $set: {
                    status,
                    updatedAt: new Date()
                },
                $push: {
                    statusHistory: {
                        status,
                        updatedBy: req.user.email,
                        updatedByRole: req.user.role,
                        timestamp: new Date(),
                        comment: comment || `Status updated to ${status}`
                    }
                }
            }
        );

        res.json({ message: 'Issue status updated successfully' });
    } catch (error) {
        console.error('Status update error:', error);
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

// Update user role or premium status (Admin only)
app.patch('/api/users/:id', authenticateToken, authorizeRole('admin'), async (req, res) => {
    try {
        if (!dbConnected) {
            return res.status(503).json({ message: 'Database not connected' });
        }

        const { role, isPremium } = req.body;
        const updateFields = { updatedAt: new Date() };

        if (role) updateFields.role = role;
        if (isPremium !== undefined) updateFields.isPremium = isPremium;

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

// ============ DASHBOARD STATS ============

// Get dashboard statistics
app.get('/api/stats', authenticateToken, authorizeRole('admin', 'staff'), async (req, res) => {
    try {
        if (!dbConnected) {
            return res.status(503).json({ message: 'Database not connected' });
        }

        const totalIssues = await db.collection('issues').countDocuments();
        const pendingIssues = await db.collection('issues').countDocuments({ status: 'pending' });
        const inProgressIssues = await db.collection('issues').countDocuments({ status: 'in-progress' });
        const resolvedIssues = await db.collection('issues').countDocuments({ status: 'resolved' });
        const closedIssues = await db.collection('issues').countDocuments({ status: 'closed' });

        const totalUsers = await db.collection('users').countDocuments();
        const premiumUsers = await db.collection('users').countDocuments({ isPremium: true });
        const staffCount = await db.collection('users').countDocuments({ role: 'staff' });

        // Issue breakdown by category
        const categoryStats = await db.collection('issues').aggregate([
            { $group: { _id: '$category', count: { $sum: 1 } } }
        ]).toArray();

        res.json({
            issues: {
                total: totalIssues,
                pending: pendingIssues,
                inProgress: inProgressIssues,
                resolved: resolvedIssues,
                closed: closedIssues
            },
            users: {
                total: totalUsers,
                premium: premiumUsers,
                staff: staffCount
            },
            categoryBreakdown: categoryStats
        });
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
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📍 API: http://localhost:${PORT}`);
});

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('\n🛑 Shutting down gracefully...');
    await client.close();
    process.exit(0);
});
