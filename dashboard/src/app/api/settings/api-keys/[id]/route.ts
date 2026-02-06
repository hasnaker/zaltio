import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';

// DELETE /api/settings/api-keys/[id] - Delete an API key
export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const cookieStore = await cookies();
    const sessionToken = cookieStore.get('zalt_session')?.value;

    if (!sessionToken) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { id: keyId } = await params;

    if (!keyId) {
      return NextResponse.json({ error: 'Key ID required' }, { status: 400 });
    }

    // TODO: Get user ID from session
    const userId = 'user_123';

    // TODO: Delete from DynamoDB
    // await dynamodb.delete({
    //   TableName: 'zalt-api-keys',
    //   Key: {
    //     PK: `USER#${userId}`,
    //     SK: `APIKEY#${keyId}`,
    //   },
    //   ConditionExpression: 'attribute_exists(PK)', // Ensure key belongs to user
    // });

    console.log('API key deleted:', { userId, keyId });

    return NextResponse.json({ success: true, message: 'API key deleted' });
  } catch (error) {
    console.error('API key deletion error:', error);
    return NextResponse.json({ error: 'Failed to delete API key' }, { status: 500 });
  }
}
