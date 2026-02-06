/**
 * Reset Local DynamoDB for Clinisyn
 * Tüm kullanıcıları siler, realm'i korur
 * 
 * Run: npx ts-node scripts/reset-local-clinisyn.ts
 */

import { DynamoDBClient, CreateTableCommand, DeleteTableCommand, ListTablesCommand, ScanCommand, DeleteItemCommand } from '@aws-sdk/client-dynamodb';

const LOCAL_ENDPOINT = 'http://localhost:8000';
const REGION = 'eu-central-1';

const client = new DynamoDBClient({
  endpoint: LOCAL_ENDPOINT,
  region: REGION,
  credentials: {
    accessKeyId: 'local',
    secretAccessKey: 'local'
  }
});

const TABLES = {
  users: 'zalt-users',
  sessions: 'zalt-sessions',
  realms: 'zalt-realms'
};

async function createTables() {
  console.log('📦 Tablolar oluşturuluyor...\n');

  // Users table
  try {
    await client.send(new CreateTableCommand({
      TableName: TABLES.users,
      KeySchema: [
        { AttributeName: 'PK', KeyType: 'HASH' },
        { AttributeName: 'SK', KeyType: 'RANGE' }
      ],
      AttributeDefinitions: [
        { AttributeName: 'PK', AttributeType: 'S' },
        { AttributeName: 'SK', AttributeType: 'S' },
        { AttributeName: 'GSI1PK', AttributeType: 'S' },
        { AttributeName: 'GSI1SK', AttributeType: 'S' }
      ],
      GlobalSecondaryIndexes: [
        {
          IndexName: 'GSI1',
          KeySchema: [
            { AttributeName: 'GSI1PK', KeyType: 'HASH' },
            { AttributeName: 'GSI1SK', KeyType: 'RANGE' }
          ],
          Projection: { ProjectionType: 'ALL' },
          ProvisionedThroughput: { ReadCapacityUnits: 5, WriteCapacityUnits: 5 }
        }
      ],
      ProvisionedThroughput: { ReadCapacityUnits: 5, WriteCapacityUnits: 5 }
    }));
    console.log(`✅ ${TABLES.users} oluşturuldu`);
  } catch (e: any) {
    if (e.name === 'ResourceInUseException') {
      console.log(`⚠️  ${TABLES.users} zaten var`);
    } else throw e;
  }

  // Sessions table
  try {
    await client.send(new CreateTableCommand({
      TableName: TABLES.sessions,
      KeySchema: [
        { AttributeName: 'PK', KeyType: 'HASH' },
        { AttributeName: 'SK', KeyType: 'RANGE' }
      ],
      AttributeDefinitions: [
        { AttributeName: 'PK', AttributeType: 'S' },
        { AttributeName: 'SK', AttributeType: 'S' }
      ],
      ProvisionedThroughput: { ReadCapacityUnits: 5, WriteCapacityUnits: 5 }
    }));
    console.log(`✅ ${TABLES.sessions} oluşturuldu`);
  } catch (e: any) {
    if (e.name === 'ResourceInUseException') {
      console.log(`⚠️  ${TABLES.sessions} zaten var`);
    } else throw e;
  }

  // Realms table
  try {
    await client.send(new CreateTableCommand({
      TableName: TABLES.realms,
      KeySchema: [
        { AttributeName: 'PK', KeyType: 'HASH' },
        { AttributeName: 'SK', KeyType: 'RANGE' }
      ],
      AttributeDefinitions: [
        { AttributeName: 'PK', AttributeType: 'S' },
        { AttributeName: 'SK', AttributeType: 'S' }
      ],
      ProvisionedThroughput: { ReadCapacityUnits: 5, WriteCapacityUnits: 5 }
    }));
    console.log(`✅ ${TABLES.realms} oluşturuldu`);
  } catch (e: any) {
    if (e.name === 'ResourceInUseException') {
      console.log(`⚠️  ${TABLES.realms} zaten var`);
    } else throw e;
  }
}

async function clearUsersTable() {
  console.log('\n🗑️  Kullanıcılar siliniyor...\n');

  const scanResult = await client.send(new ScanCommand({
    TableName: TABLES.users
  }));

  if (!scanResult.Items || scanResult.Items.length === 0) {
    console.log('ℹ️  Kullanıcı tablosu zaten boş');
    return;
  }

  let deleted = 0;
  for (const item of scanResult.Items) {
    await client.send(new DeleteItemCommand({
      TableName: TABLES.users,
      Key: {
        PK: item.PK,
        SK: item.SK
      }
    }));
    deleted++;
  }

  console.log(`✅ ${deleted} kayıt silindi`);
}

async function clearSessionsTable() {
  console.log('\n🗑️  Sessionlar siliniyor...\n');

  const scanResult = await client.send(new ScanCommand({
    TableName: TABLES.sessions
  }));

  if (!scanResult.Items || scanResult.Items.length === 0) {
    console.log('ℹ️  Session tablosu zaten boş');
    return;
  }

  let deleted = 0;
  for (const item of scanResult.Items) {
    await client.send(new DeleteItemCommand({
      TableName: TABLES.sessions,
      Key: {
        PK: item.PK,
        SK: item.SK
      }
    }));
    deleted++;
  }

  console.log(`✅ ${deleted} session silindi`);
}

async function main() {
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║         LOCAL DYNAMODB RESET - CLINISYN                    ║');
  console.log('╚════════════════════════════════════════════════════════════╝\n');

  // Create tables if not exist
  await createTables();

  // Clear users
  await clearUsersTable();

  // Clear sessions
  await clearSessionsTable();

  console.log('\n╔════════════════════════════════════════════════════════════╗');
  console.log('║                    ✅ TAMAMLANDI!                          ║');
  console.log('║                                                            ║');
  console.log('║  Local DynamoDB sıfırlandı.                               ║');
  console.log('║  Yeni kayıt olabilirsin!                                  ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
}

main().catch(console.error);
