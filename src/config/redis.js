const Redis = require('ioredis');

let redis;

function createRedisClient() {
  const client = new Redis(process.env.REDIS_URL, {
    tls: { rejectUnauthorized: false },
    connectTimeout: 10000,
    maxRetriesPerRequest: 3,
    retryStrategy(times) {
      if (times > 3) return null; // stop retrying
      return Math.min(times * 500, 2000);
    },
    lazyConnect: true
  });

  client.on('error', () => {}); // suppress unhandled error events

  return client;
}

async function connectRedis() {
  try {
    redis = createRedisClient();
    await redis.connect();
    await redis.ping();
    console.log('Redis connected');
  } catch (error) {
    console.warn('Redis unavailable — caching disabled:', error.message);
    redis = null; // app runs without cache
  }
}

// Safe get — returns null if Redis is down
async function cacheGet(key) {
  if (!redis) return null;
  try {
    const val = await redis.get(key);
    return val ? JSON.parse(val) : null;
  } catch {
    return null;
  }
}

// Safe set — silently fails if Redis is down
async function cacheSet(key, value, ttlSeconds = 86400) {
  if (!redis) return;
  try {
    await redis.set(key, JSON.stringify(value), 'EX', ttlSeconds);
  } catch {
    // silent fail
  }
}

module.exports = { connectRedis, cacheGet, cacheSet };