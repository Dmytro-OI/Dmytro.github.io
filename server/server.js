const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const admin = require('firebase-admin');
const path = require('path');

// Load environment variables
dotenv.config();

// Initialize Firebase Admin with service account
const serviceAccount = require('./serviceAccountKey.json');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../build')));

// Authentication Middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Routes
app.post('/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    
    // Check if user already exists
    const userRef = db.collection('users').doc(email);
    const doc = await userRef.get();
    
    if (doc.exists) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user in Firestore
    await userRef.set({
      email,
      name,
      password: hashedPassword,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Get user from Firestore
    const userRef = db.collection('users').doc(email);
    const doc = await userRef.get();

    if (!doc.exists) {
      return res.status(400).json({ error: 'User not found' });
    }

    const user = doc.data();

    // Validate password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid password' });
    }

    // Create and assign token
    const token = jwt.sign(
      { email: user.email, name: user.name },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const userRef = db.collection('users').doc(req.user.email);
    const doc = await userRef.get();
    
    if (!doc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userData = doc.data();
    delete userData.password; // Don't send password to client
    
    res.json(userData);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Language Learning Platform Routes

// Get completed lessons
app.get('/api/completed-lessons', authenticateToken, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    let query = db.collection('completedLessons')
                  .where('userId', '==', req.user.email);
    
    if (startDate && endDate) {
      query = query.where('completedAt', '>=', new Date(startDate))
                  .where('completedAt', '<=', new Date(endDate));
    }

    const snapshot = await query.orderBy('completedAt', 'desc').get();
    const lessons = [];
    
    snapshot.forEach(doc => {
      lessons.push({
        id: doc.id,
        ...doc.data(),
        completedAt: doc.data().completedAt.toDate()
      });
    });

    res.json(lessons);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Mark lesson as completed
app.post('/api/complete-lesson', authenticateToken, async (req, res) => {
  try {
    const { lessonId, lessonTitle } = req.body;
    
    const completedLesson = {
      lessonId,
      lessonTitle,
      userId: req.user.email,
      userName: req.user.name,
      completedAt: admin.firestore.FieldValue.serverTimestamp()
    };

    await db.collection('completedLessons').add(completedLesson);
    
    res.status(201).json({ message: 'Lesson marked as completed' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Serve static files for production
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../build', 'index.html'));
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
}); 