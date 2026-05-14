require('dotenv').config();
const express  = require('express');
const helmet   = require('helmet');
const cors     = require('cors');
const { connectRedis } = require('./config/redis');
const { testDB }       = require('./config/db');
const { limiter }      = require('./middleware/rateLimit');

const app = express();app.use(helmet());
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

// Backward-compatible aliases (without /api prefix)
app.use('/auth',    require('./routes/auth'));
app.use('/check',   require('./routes/check'));
app.use('/history', require('./routes/history'));

// Handle malformed JSON payloads from express.json()
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({
      error: 'Invalid JSON body',
      message: err.message
    });
  }
  next(err);
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Route not found',
    available_routes: [
      'POST /api/auth/token',
      'POST /api/check',
      'GET /api/history',
      'POST /auth/token',
      'POST /check',
      'GET /history'
    ]
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.message);
  res.status(500).json({
    error: 'Internal server error',
    message: err.message
  });
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