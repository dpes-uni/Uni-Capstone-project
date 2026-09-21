// MongoDB init script (runs once on first container start).
// Creates the database and an initial empty collection so the app starts clean.
db = db.getSiblingDB('assure_docs');
db.createCollection('users');
db.users.createIndex({ email: 1 }, { unique: true });