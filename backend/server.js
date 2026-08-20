require('dotenv').config();
const app = require('./src/app');
const connectDB = require('./src/config/db');
const { verifyEmailTransport } = require('./src/utils/sendEmail');
const logger = require('./src/utils/logger');

const PORT = process.env.PORT || 5001;

const start = async () => {
  try {
    await connectDB();
    await verifyEmailTransport();
    app.listen(PORT, () => {
      logger.info('Assure Docs API started', {
        environment: process.env.NODE_ENV || 'development',
        port: PORT,
        health: `http://localhost:${PORT}/api/health`,
      });
    });
  } catch (err) {
    logger.error('Failed to start server', { error: err.message });
    process.exit(1);
  }
};

start();

process.on('unhandledRejection', (err) => {
  logger.error('Unhandled Rejection', { error: err.message, stack: err.stack });
});
