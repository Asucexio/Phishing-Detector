require('dotenv').config();
const express  = require('express');
const helmet   = require('helmet');
const cors     = require('cors');
const { connectRedis } = require('./config/redis');
const { testDB }       = require('./config/db');
const { limiter }      = require('./middleware/rateLimit');

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(limiter);

// Health check
app.get('/', (req, res) => {
  res.json({
    status:  'running',
    project: 'Phishing Detector API',
    version: '1.0.0',
    author:  'INSA Ethiopia',
    endpoints: {
      auth:    'POST /api/auth/token',
      check:   'POST /api/check',
      history: 'GET  /api/history'
    }
  });
});

// Routes
app.use('/api/auth',    require('./routes/auth'));
app.use('/api/check',   require('./routes/check'));
app.use('/api/history', require('./routes/history'));

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.message);
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 3000;

async function startServer() {
  await connectRedis();
  await testDB();
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();