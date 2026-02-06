/**
 * Tediyat Invitation Repository - DynamoDB operations for invitations
 * Validates: Requirements 12.2, 12.7
 */

import {
  GetCommand,
  PutCommand,
  UpdateCommand,
  QueryCommand,
  DeleteCommand,
} from '@aws-sdk/lib-dynamodb';
import { dynamoDb } from '../../services/dynamodb.service';
import {
  Invitation,
  InvitationDynamoDBItem,
  CreateInvitationInput,
  InvitationStatus,
  generateInvitationId,
  generateInvitationToken,
  hashInvitationToken,
  calculateExpiryDate,
  calculateTTL,
} from '../../models/tediyat/invitation.model';

const TABLE_NAME = process.env.TEDIYAT_TABLE || 'zalt-tediyat';

/**
 * Convert DynamoDB item to Invitation
 */
function itemToInvitation(item: InvitationDynamoDBItem): Invitation {
  return {
    id: item.id,
    tenant_id: item.tenant_id,
    tenant_name: item.tenant_name,
    email: item.email,
    role_id: item.role_id,
    role_name: item.role_name,
    direct_permissions: item.direct_permissions,
    token: item.token,
    status: item.status,
    invited_by: item.invited_by,
    invited_by_name: item.invited_by_name,
    expires_at: item.expires_at,
    created_at: item.created_at,
    accepted_at: item.accepted_at,
    accepted_by: item.accepted_by,
  };
}

/**
 * Create a new invitation
 * Returns both the invitation and the raw token (for email)
 */
export async function createInvitation(
  input: CreateInvitationInput
): Promise<{ invitation: Invitation; rawToken: string }> {
  const now = new Date().toISOString();
  const invitationId = generateInvitationId();
  const { rawToken, hashedToken } = generateInvitationToken();
  const expiresAt = calculateExpiryDate();
  const ttl = calculateTTL();

  const item: InvitationDynamoDBItem = {
    PK: `INVITATION#${invitationId}`,
    SK: 'METADATA',
    GSI1PK: `TENANT#${input.tenant_id}#INVITATIONS`,
    GSI1SK: `STATUS#pending#CREATED#${now}`,
    GSI2PK: `TOKEN#${hashedToken}`,
    GSI2SK: 'INVITATION',
    GSI3PK: `EMAIL#${input.email.toLowerCase()}#INVITATIONS`,
    GSI3SK: `TENANT#${input.tenant_id}`,
    
    id: invitationId,
    tenant_id: input.tenant_id,
    tenant_name: input.tenant_name,
    email: input.email.toLowerCase(),
    role_id: input.role_id,
    role_name: input.role_name,
    direct_permissions: input.direct_permissions,
    token: hashedToken,
    status: 'pending',
    invited_by: input.invited_by,
    invited_by_name: input.invited_by_name,
    expires_at: expiresAt,
    created_at: now,
    ttl,
    entity_type: 'INVITATION',
  };

  await dynamoDb.send(new PutCommand({
    TableName: TABLE_NAME,
    Item: item,
    ConditionExpression: 'attribute_not_exists(PK)',
  }));

  return {
    invitation: itemToInvitation(item),
    rawToken,
  };
}

/**
 * Get invitation by ID
 */
export async function getInvitation(invitationId: string): Promise<Invitation | null> {
  const result = await dynamoDb.send(new GetCommand({
    TableName: TABLE_NAME,
    Key: {
      PK: `INVITATION#${invitationId}`,
      SK: 'METADATA',
    },
  }));

  if (!result.Item) {
    return null;
  }

  return itemToInvitation(result.Item as InvitationDynamoDBItem);
}

/**
 * Get invitation by token
 */
export async function getInvitationByToken(rawToken: string): Promise<Invitation | null> {
  const hashedToken = hashInvitationToken(rawToken);
  
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: 'GSI2',
    KeyConditionExpression: 'GSI2PK = :tokenPk AND GSI2SK = :sk',
    ExpressionAttributeValues: {
      ':tokenPk': `TOKEN#${hashedToken}`,
      ':sk': 'INVITATION',
    },
    Limit: 1,
  }));

  if (!result.Items || result.Items.length === 0) {
    return null;
  }

  return itemToInvitation(result.Items[0] as InvitationDynamoDBItem);
}

/**
 * List pending invitations for a tenant
 */
export async function listTenantInvitations(
  tenantId: string,
  status?: InvitationStatus,
  limit: number = 50,
  cursor?: string
): Promise<{ invitations: Invitation[]; nextCursor?: string }> {
  let keyCondition = 'GSI1PK = :tenantPk';
  const expressionValues: Record<string, unknown> = {
    ':tenantPk': `TENANT#${tenantId}#INVITATIONS`,
  };

  if (status) {
    keyCondition += ' AND begins_with(GSI1SK, :statusPrefix)';
    expressionValues[':statusPrefix'] = `STATUS#${status}`;
  }

  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: 'GSI1',
    KeyConditionExpression: keyCondition,
    ExpressionAttributeValues: expressionValues,
    Limit: limit,
    ExclusiveStartKey: cursor ? JSON.parse(Buffer.from(cursor, 'base64').toString()) : undefined,
    ScanIndexForward: false, // Newest first
  }));

  const invitations = (result.Items || []).map(item => 
    itemToInvitation(item as InvitationDynamoDBItem)
  );

  return {
    invitations,
    nextCursor: result.LastEvaluatedKey 
      ? Buffer.from(JSON.stringify(result.LastEvaluatedKey)).toString('base64')
      : undefined,
  };
}

/**
 * Check if user already has pending invitation to tenant
 */
export async function hasPendingInvitation(
  email: string,
  tenantId: string
): Promise<boolean> {
  const result = await dynamoDb.send(new QueryCommand({
    TableName: TABLE_NAME,
    IndexName: 'GSI3',
    KeyConditionExpression: 'GSI3PK = :emailPk AND GSI3SK = :tenantSk',
    FilterExpression: '#status = :pending',
    ExpressionAttributeNames: {
      '#status': 'status',
    },
    ExpressionAttributeValues: {
      ':emailPk': `EMAIL#${email.toLowerCase()}#INVITATIONS`,
      ':tenantSk': `TENANT#${tenantId}`,
      ':pending': 'pending',
    },
    Limit: 1,
  }));

  return (result.Items?.length || 0) > 0;
}

/**
 * Update invitation status
 */
export async function updateInvitationStatus(
  invitationId: string,
  status: InvitationStatus,
  acceptedBy?: string
): Promise<Invitation | null> {
  const now = new Date().toISOString();
  const updateExpressions: string[] = [
    '#status = :status',
    'GSI1SK = :gsi1sk',
  ];
  const expressionAttributeNames: Record<string, string> = {
    '#status': 'status',
  };
  const expressionAttributeValues: Record<string, unknown> = {
    ':status': status,
  };

  // Get existing to update GSI1SK
  const existing = await getInvitation(invitationId);
  if (!existing) {
    return null;
  }

  expressionAttributeValues[':gsi1sk'] = `STATUS#${status}#CREATED#${existing.created_at}`;

  if (status === 'accepted' && acceptedBy) {
    updateExpressions.push('accepted_at = :acceptedAt');
    updateExpressions.push('accepted_by = :acceptedBy');
    expressionAttributeValues[':acceptedAt'] = now;
    expressionAttributeValues[':acceptedBy'] = acceptedBy;
  }

  const result = await dynamoDb.send(new UpdateCommand({
    TableName: TABLE_NAME,
    Key: {
      PK: `INVITATION#${invitationId}`,
      SK: 'METADATA',
    },
    UpdateExpression: `SET ${updateExpressions.join(', ')}`,
    ExpressionAttributeNames: expressionAttributeNames,
    ExpressionAttributeValues: expressionAttributeValues,
    ReturnValues: 'ALL_NEW',
  }));

  if (!result.Attributes) {
    return null;
  }

  return itemToInvitation(result.Attributes as InvitationDynamoDBItem);
}

/**
 * Delete invitation (hard delete)
 */
export async function deleteInvitation(invitationId: string): Promise<boolean> {
  try {
    await dynamoDb.send(new DeleteCommand({
      TableName: TABLE_NAME,
      Key: {
        PK: `INVITATION#${invitationId}`,
        SK: 'METADATA',
      },
    }));
    return true;
  } catch {
    return false;
  }
}
