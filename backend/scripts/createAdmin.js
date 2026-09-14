require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('../src/models/User');

async function main() {
  const { MONGO_URI, ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_NAME } = process.env;
  if (!MONGO_URI || !ADMIN_EMAIL || !ADMIN_PASSWORD) {
    throw new Error('Set MONGO_URI, ADMIN_EMAIL and ADMIN_PASSWORD in backend/.env before running this script.');
  }

  await mongoose.connect(MONGO_URI);
  const email = ADMIN_EMAIL.toLowerCase();
  const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 12);
  const existing = await User.findOne({ email });

  if (existing) {
    existing.role = 'admin';
    existing.passwordHash = passwordHash;
    existing.name = ADMIN_NAME || existing.name;
    existing.isVerified = true;
    await existing.save();
    console.log(`Updated ${email} as an administrator.`);
  } else {
    await User.create({
      name: ADMIN_NAME || 'Assure Docs Administrator',
      email,
      passwordHash,
      role: 'admin',
      isVerified: true,
    });
    console.log(`Created administrator ${email}.`);
  }

  await mongoose.disconnect();
}

main().catch(async (err) => {
  console.error(err.message);
  try { await mongoose.disconnect(); } catch {}
  process.exit(1);
});
