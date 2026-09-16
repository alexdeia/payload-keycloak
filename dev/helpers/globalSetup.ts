import { MongoMemoryReplSet } from 'mongodb-memory-server'

let memoryDB: MongoMemoryReplSet | undefined

/** One in-memory MongoDB for the whole run: every spec file gets the same DATABASE_URL. */
export async function setup() {
  memoryDB = await MongoMemoryReplSet.create({
    replSet: { count: 3, dbName: 'payloadmemory' },
  })
  process.env.DATABASE_URL = `${memoryDB.getUri()}&retryWrites=true`
}

export async function teardown() {
  await memoryDB?.stop()
}
