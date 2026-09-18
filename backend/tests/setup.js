/**
 * Test infrastructure setup for MongoMemoryServer.
 *
 * The cached MongoDB binary (mongodb-windows-x86_64-8.2.6.zip) has a
 * corrupted MD5 and cannot be re-downloaded (network returns 403/404).
 * A system MongoDB installation exists at:
 *   C:/Program Files/MongoDB/Server/8.3/bin/mongod.exe
 * Configure mongodb-memory-server to use it directly and skip MD5/version
 * checks that would fail against the 8.3 binary.
 *
 * This is test-environment configuration only — no production code is changed.
 */
process.env.MONGOMS_SYSTEM_BINARY = 'C:/Program Files/MongoDB/Server/8.3/bin/mongod.exe';
process.env.MONGOMS_MD5_CHECK = 'false';
process.env.MONGOMS_SYSTEM_BINARY_VERSION_CHECK = 'false';
