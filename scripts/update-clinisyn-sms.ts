import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, UpdateCommand, GetCommand } from '@aws-sdk/lib-dynamodb';

const client = new DynamoDBClient({ region: 'eu-central-1' });
const docClient = DynamoDBDocumentClient.from(client);

async function updateClinisyn() {
  // First get current settings
  const getCmd = new GetCommand({
    TableName: 'zalt-realms',
    Key: { pk: 'REALM#clinisyn', sk: 'REALM#clinisyn' }
  });
  
  const current = await docClient.send(getCmd);
  console.log('Current realm:', JSON.stringify(current.Item, null, 2));
  
  // Update with SMS MFA enabled
  const updateCmd = new UpdateCommand({
    TableName: 'zalt-realms',
    Key: { pk: 'REALM#clinisyn', sk: 'REALM#clinisyn' },
    UpdateExpression: 'SET mfa_config = :mfa, updated_at = :now',
    ExpressionAttributeValues: {
      ':mfa': {
        allowed_methods: ['totp', 'webauthn', 'email', 'sms'],
        sms_risk_accepted: true,
        default_method: 'totp',
        required: false,
        grace_period_days: 7
      },
      ':now': new Date().toISOString()
    },
    ReturnValues: 'ALL_NEW'
  });
  
  const result = await docClient.send(updateCmd);
  console.log('\n✅ Updated realm MFA config:', JSON.stringify(result.Attributes?.mfa_config, null, 2));
}

updateClinisyn().catch(console.error);
