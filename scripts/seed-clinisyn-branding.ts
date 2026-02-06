/**
 * Seed Clinisyn Realm Branding
 * 
 * Bu script Clinisyn realm'lerine email branding ekler.
 * Email'ler "Clinisyn" adıyla gönderilir, "Zalt.io" değil.
 * 
 * Kullanım:
 *   npx ts-node scripts/seed-clinisyn-branding.ts
 * 
 * NOT: AWS SES'te clinisyn.com domain'i verified olmalı!
 */

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, UpdateCommand, GetCommand } from '@aws-sdk/lib-dynamodb';

const client = new DynamoDBClient({ region: 'eu-central-1' });
const docClient = DynamoDBDocumentClient.from(client);

const REALMS_TABLE = 'zalt-realms';

// Clinisyn Branding Configuration
const CLINISYN_BRANDING = {
  display_name: 'Clinisyn',
  email_from_address: 'noreply@clinisyn.com',
  email_from_name: 'Clinisyn',
  support_email: 'support@clinisyn.com',
  app_url: 'https://app.clinisyn.com',
  logo_url: 'https://clinisyn.com/logo.png',
  primary_color: '#2563eb',
  privacy_policy_url: 'https://clinisyn.com/privacy',
  terms_of_service_url: 'https://clinisyn.com/terms'
};

const CLINISYN_REALMS = [
  'clinisyn-psychologists',
  'clinisyn-students'
];

async function updateRealmBranding(realmId: string) {
  console.log(`\nUpdating branding for realm: ${realmId}`);
  
  // First, get current realm data
  const getResult = await docClient.send(new GetCommand({
    TableName: REALMS_TABLE,
    Key: { realmId }
  }));

  if (!getResult.Item) {
    console.log(`  ❌ Realm not found: ${realmId}`);
    return false;
  }

  console.log(`  ✓ Found realm: ${getResult.Item.name}`);

  // Update with branding
  const currentSettings = getResult.Item.settings || {};
  const updatedSettings = {
    ...currentSettings,
    branding: CLINISYN_BRANDING
  };

  await docClient.send(new UpdateCommand({
    TableName: REALMS_TABLE,
    Key: { realmId },
    UpdateExpression: 'SET settings = :settings, updated_at = :updated_at',
    ExpressionAttributeValues: {
      ':settings': updatedSettings,
      ':updated_at': new Date().toISOString()
    }
  }));

  console.log(`  ✓ Branding updated successfully`);
  console.log(`    - Display Name: ${CLINISYN_BRANDING.display_name}`);
  console.log(`    - Email From: ${CLINISYN_BRANDING.email_from_name} <${CLINISYN_BRANDING.email_from_address}>`);
  console.log(`    - Support: ${CLINISYN_BRANDING.support_email}`);
  console.log(`    - App URL: ${CLINISYN_BRANDING.app_url}`);
  
  return true;
}

async function main() {
  console.log('='.repeat(60));
  console.log('Clinisyn Realm Branding Seed Script');
  console.log('='.repeat(60));
  console.log('\nThis will update the following realms with Clinisyn branding:');
  CLINISYN_REALMS.forEach(r => console.log(`  - ${r}`));
  
  console.log('\n⚠️  IMPORTANT: Make sure clinisyn.com is verified in AWS SES!');
  console.log('   Otherwise emails will fail to send.\n');

  let successCount = 0;
  for (const realmId of CLINISYN_REALMS) {
    try {
      const success = await updateRealmBranding(realmId);
      if (success) successCount++;
    } catch (error) {
      console.error(`  ❌ Error updating ${realmId}:`, (error as Error).message);
    }
  }

  console.log('\n' + '='.repeat(60));
  console.log(`Done! Updated ${successCount}/${CLINISYN_REALMS.length} realms.`);
  console.log('='.repeat(60));
}

main().catch(console.error);
