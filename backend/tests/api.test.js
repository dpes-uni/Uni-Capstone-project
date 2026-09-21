process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-jwt-secret';

const request = require('supertest');
const app = require('../src/app');

describe('API surface', () => {
  test('GET /api/health returns ok', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.service).toBe('assure-docs-backend');
  });

  test('GET /api/health includes dependency and process details', async () => {
    const res = await request(app).get('/api/health');
    expect(res.body).toHaveProperty('uptime');
    expect(res.body).toHaveProperty('timestamp');
    expect(res.body.database.state).toBeDefined();
    expect(res.body.aiService).toMatch(/healthy|unavailable|unknown/);
    expect(res.body.memory).toHaveProperty('heapUsedMb');
  });

  test('GET /api/health/ready reports 503 when the database is not connected', async () => {
    const res = await request(app).get('/api/health/ready');
    expect(res.status).toBe(503);
    expect(res.body.status).toBe('not_ready');
  });

  test('unknown routes return 404 JSON', async () => {
    const res = await request(app).get('/api/does-not-exist');
    expect(res.status).toBe(404);
    expect(res.body).toHaveProperty('message');
  });

  test('security headers are set by helmet', async () => {
    const res = await request(app).get('/api/health');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-frame-options']).toBe('SAMEORIGIN');
    expect(res.headers['x-dns-prefetch-control']).toBe('off');
    expect(res.headers['strict-transport-security']).toBeUndefined(); // HSTS only in production
  });

  test('CORS allows the configured client origin', async () => {
    const res = await request(app).get('/api/health').set('Origin', 'http://localhost:5173');
    expect(res.headers['access-control-allow-origin']).toBe('http://localhost:5173');
  });
});