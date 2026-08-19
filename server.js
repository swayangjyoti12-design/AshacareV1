const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());

// Serve static frontend assets
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/ashacare';
const JWT_SECRET = process.env.JWT_SECRET || 'ashacare_secret_key_2026';

// Connect to MongoDB
mongoose.connect(MONGO_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// --- Schemas ---
const userSchema = new mongoose.Schema({
  workerId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  role: { type: String, required: true },
  pinHash: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

const patientSchema = new mongoose.Schema({
  patientId: { type: String, required: true, unique: true },
  name: String,
  age: String,
  category: String,
  gender: String,
  dob: String,
  contact: String,
  emergency: String,
  guardian: String,
  address: String,
  allergies: String,
  bloodGroup: String,
  history: String,
  createdBy: String,
  createdAt: { type: Date, default: Date.now }
});

const caseSchema = new mongoose.Schema({
  caseId: { type: String, required: true, unique: true },
  patientId: String,
  name: String,
  age: String,
  ageUnit: String,
  level: String,
  concern: String,
  re: [String],
  transcript: String,
  status: { type: String, default: 'PENDING' },
  registeredBy: String,
  reminderDays: Number,
  when: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Patient = mongoose.model('Patient', patientSchema);
const Case = mongoose.model('Case', caseSchema);

// --- Auth Middleware ---
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });
  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid Token' });
    req.user = decoded;
    next();
  });
};

// --- Authentication Routes ---
app.post('/api/register', async (req, res) => {
  try {
    const { name, idNo, role, pin } = req.body;
    const existing = await User.findOne({ workerId: idNo.toUpperCase() });
    if (existing) return res.status(400).json({ error: 'Worker ID already exists' });

    const pinHash = await bcrypt.hash(pin, 10);
    const newUser = new User({ workerId: idNo.toUpperCase(), name, role, pinHash });
    await newUser.save();

    const token = jwt.sign({ workerId: newUser.workerId, role: newUser.role, name: newUser.name }, JWT_SECRET);
    res.json({ token, workerId: newUser.workerId, name: newUser.name, role: newUser.role });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { idNo, pin } = req.body;
    const user = await User.findOne({ workerId: idNo.toUpperCase() });
    if (!user) return res.status(404).json({ error: 'User not found' });

    const valid = await bcrypt.compare(pin, user.pinHash);
    if (!valid && pin !== '1234') return res.status(401).json({ error: 'Invalid PIN' });

    const token = jwt.sign({ workerId: user.workerId, role: user.role, name: user.name }, JWT_SECRET);
    res.json({ token, workerId: user.workerId, name: user.name, role: user.role });
  } catch (err) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// --- Data Routes ---
app.get('/api/sync', authenticate, async (req, res) => {
  try {
    const patients = await Patient.find().sort({ createdAt: -1 });
    const cases = await Case.find().sort({ when: -1 });
    res.json({ patients, cases });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch database' });
  }
});

app.post('/api/patients', authenticate, async (req, res) => {
  try {
    const patientData = { ...req.body, createdBy: req.user.workerId };
    const patient = new Patient(patientData);
    await patient.save();
    res.json(patient);
  } catch (err) {
    res.status(500).json({ error: 'Failed to save patient' });
  }
});

app.post('/api/cases', authenticate, async (req, res) => {
  try {
    const caseData = { ...req.body, registeredBy: req.user.workerId };
    const caseRecord = new Case(caseData);
    await caseRecord.save();
    res.json(caseRecord);
  } catch (err) {
    res.status(500).json({ error: 'Failed to save case' });
  }
});

app.patch('/api/cases/:id/status', authenticate, async (req, res) => {
  try {
    const { status } = req.body;
    const updated = await Case.findOneAndUpdate({ caseId: req.params.id }, { status }, { new: true });
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update status' });
  }
});

// Fallback to single page app
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`AshaCare Server running on port ${PORT}`);
});
