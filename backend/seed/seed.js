/**
 * Optional demo data seeder.
 * Run with: npm run seed  (from the backend folder, after configuring .env)
 *
 * Creates one verified demo user and a couple of sample assessments so you
 * have something to look at immediately after cloning.
 */
require('dotenv').config();
const bcrypt = require('bcryptjs');
const connectDB = require('../src/config/db');
const User = require('../src/models/User');
const Assessment = require('../src/models/Assessment');

const DEMO_EMAIL = 'demo@assuredocs.test';
const DEMO_PASSWORD = 'Password123!';

async function seed() {
  await connectDB();

  let user = await User.findOne({ email: DEMO_EMAIL });
  if (!user) {
    const passwordHash = await bcrypt.hash(DEMO_PASSWORD, 12);
    user = await User.create({
      name: 'Demo User',
      email: DEMO_EMAIL,
      passwordHash,
      role: 'student',
      isVerified: true,
    });
    console.log(`Created demo user: ${DEMO_EMAIL} / ${DEMO_PASSWORD}`);
  } else {
    console.log('Demo user already exists, skipping user creation.');
  }

  const existingAssessments = await Assessment.countDocuments({ owner: user._id });
  if (existingAssessments === 0) {
    await Assessment.create([
      {
        owner: user._id,
        applicantName: 'Alex Morgan',
        documentType: 'passport',
        status: 'verified',
        riskScore: 12,
        notes: 'Passport scan matched biometric check.',
      },
      {
        owner: user._id,
        applicantName: 'Priya Sharma',
        documentType: 'academic_transcript',
        status: 'pending',
        riskScore: 45,
        notes: 'Awaiting issuing institution confirmation.',
      },
      {
        owner: user._id,
        applicantName: 'Chen Wei',
        documentType: 'national_id',
        status: 'in_review',
        riskScore: 78,
        notes: 'Flagged for manual review: image quality below threshold.',
      },
    ]);
    console.log('Created 3 sample assessments.');
  } else {
    console.log('Sample assessments already exist, skipping.');
  }

  console.log('\nSeed complete. Demo login:');
  console.log(`  email:    ${DEMO_EMAIL}`);
  console.log(`  password: ${DEMO_PASSWORD}`);
  process.exit(0);
}

seed().catch((err) => {
  console.error('Seeding failed:', err);
  process.exit(1);
});
