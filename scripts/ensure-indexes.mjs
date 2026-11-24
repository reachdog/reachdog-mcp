// Operator script: creates the TTL and lookup indexes the hosted connector needs.
// Reads MONGO_URI (required) and MONGO_DB (default rlly_meloquent). Safe to run repeatedly.
import { MongoClient } from 'mongodb';
import { HostedStore } from '../dist/hosted/store.js';

const uri = process.env.MONGO_URI;
if (!uri) {
  process.stderr.write('ensure-indexes: MONGO_URI is not set\n');
  process.exit(1);
}
const client = new MongoClient(uri, { serverSelectionTimeoutMS: 10000 });
try {
  await client.connect();
  await new HostedStore(client.db(process.env.MONGO_DB || 'rlly_meloquent')).ensureIndexes();
  process.stdout.write('indexes ready\n');
} catch {
  process.stderr.write('ensure-indexes: could not create indexes. Check MONGO_URI and MONGO_DB and that the user can create indexes\n');
  process.exitCode = 1;
} finally {
  await client.close().catch(() => {});
}
