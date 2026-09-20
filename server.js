const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();
const app = express();

app.use(express.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || 'render_super_secret_key';

// Middleware for token verification
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access token required' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token' });
        req.user = user;
        next();
    });
}

// --- API AUTH ---
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        let user = await prisma.user.findUnique({ where: { username } });
        
        // Auto-seed default admin if no users exist
        if (!user && username === 'admin' && password === 'admin123') {
            const hashedPassword = bcrypt.hashSync('admin123', 8);
            user = await prisma.user.create({
                data: { username: 'admin', password: hashedPassword, role: 'ADMIN' }
            });
        }

        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const token = jwt.sign({ id: user.id, role: user.role, username: user.username }, JWT_SECRET, { expiresIn: '12h' });
        res.json({ token, role: user.role, username: user.username });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// --- API CUSTOMERS ---
app.get('/api/customers', authenticateToken, async (req, res) => {
    try {
        const customers = await prisma.customer.findMany({
            include: { vehicleInfo: true, caller: { select: { username: true } } },
            orderBy: { createdAt: 'desc' }
        });
        res.json(customers);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.post('/api/customers', authenticateToken, async (req, res) => {
    try {
        const { name, phone, priority, status, brand, model, budget } = req.body;
        const customer = await prisma.customer.create({
            data: {
                name,
                phone,
                priority: priority || 'Medium',
                status: status || 'New',
                callerId: req.user.id,
                vehicleInfo: {
                    create: { brand: brand || 'Unknown', model: model || 'Unknown', budget: budget ? parseFloat(budget) : null }
                }
            },
            include: { vehicleInfo: true }
        });
        res.json(customer);
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

// --- API CALL LOGS ---
app.post('/api/calls', authenticateToken, async (req, res) => {
    try {
        const { customerId, duration, status, notes } = req.body;
        const callLog = await prisma.callLog.create({
            data: { customerId: parseInt(customerId), callerId: req.user.id, duration: parseInt(duration), status, notes }
        });

        await prisma.customer.update({
            where: { id: parseInt(customerId) },
            data: { status, lastCalledAt: new Date(), callAttempts: { increment: 1 } }
        });

        res.json(callLog);
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

// Serve Frontend HTML
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve static assets
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
