# HSD Auth Platform - Troubleshooting Guide

Common issues and their solutions.

## Authentication Issues

### "Invalid credentials" error

**Symptoms:**
- Login fails with "Invalid email or password"
- User is sure the password is correct

**Possible Causes & Solutions:**

1. **Wrong realm ID**
   ```typescript
   // Check you're using the correct realm
   const auth = new HSDAuthClient({
     realmId: 'correct-realm-id', // Verify this
     apiUrl: 'https://api.auth.hsdcore.com'
   });
   ```

2. **Email not verified**
   - Check user status in dashboard
   - Resend verification email

3. **Account suspended**
   - Check user status in dashboard
   - Activate user if appropriate

4. **Password case sensitivity**
   - Passwords are case-sensitive
   - Check for caps lock

### "Token expired" error

**Symptoms:**
- API calls fail with 401
- User was logged in but suddenly logged out

**Solutions:**

1. **Enable auto-refresh**
   ```typescript
   const auth = new HSDAuthClient({
     realmId: 'your-realm',
     apiUrl: 'https://api.auth.hsdcore.com',
     autoRefresh: true // Enable auto-refresh
   });
   ```

2. **Manual refresh**
   ```typescript
   try {
     await auth.refreshToken();
   } catch {
     // Redirect to login
     window.location.href = '/login';
   }
   ```

3. **Check session timeout**
   - Realm session timeout may be too short
   - Increase in dashboard: Realms → Edit → Session Settings

### "Rate limited" error

**Symptoms:**
- Login fails with 429 status
- "Too many requests" message

**Solutions:**

1. **Wait and retry**
   - Default: 5 attempts per 15 minutes
   - Wait for the rate limit window to reset

2. **Check for bot/script issues**
   - Ensure no automated scripts are hammering the API
   - Implement exponential backoff

3. **Contact admin**
   - Rate limits can be adjusted per realm

### Account locked

**Symptoms:**
- Login fails with "Account locked"
- 423 status code

**Solutions:**

1. **Wait for automatic unlock**
   - Default: 15 minutes after last failed attempt

2. **Admin unlock**
   - Dashboard → Users → Find user → Activate

3. **Password reset**
   - Use "Forgot password" flow

## API Issues

### CORS errors

**Symptoms:**
- Browser console shows CORS error
- "Access-Control-Allow-Origin" missing

**Solutions:**

1. **Add origin to allowed list**
   - Dashboard → Realms → Edit → Allowed Origins
   - Add your application's domain

2. **Check protocol**
   - `http://` and `https://` are different origins
   - Use HTTPS in production

3. **Check port**
   - `localhost:3000` and `localhost:3001` are different
   - Add all development ports

### "Realm not found" error

**Symptoms:**
- API returns 404
- "Realm not found" message

**Solutions:**

1. **Verify realm ID**
   ```typescript
   // Check realm ID is correct
   console.log('Using realm:', auth.config.realmId);
   ```

2. **Check realm exists**
   - Dashboard → Realms → Verify realm is listed

3. **Check realm is active**
   - Realm may have been deleted

### Network errors

**Symptoms:**
- "Network error" or "Failed to fetch"
- Requests timeout

**Solutions:**

1. **Check API URL**
   ```typescript
   // Verify API URL
   const auth = new HSDAuthClient({
     apiUrl: 'https://api.auth.hsdcore.com' // No trailing slash
   });
   ```

2. **Check internet connection**
   - Verify network connectivity

3. **Check API status**
   - Visit https://status.hsdcore.com

4. **Check firewall/proxy**
   - Corporate firewalls may block requests

## SDK Issues

### TypeScript errors

**Symptoms:**
- Type errors in IDE
- Build fails with type errors

**Solutions:**

1. **Update SDK**
   ```bash
   npm update @hsd/auth-sdk
   ```

2. **Check TypeScript version**
   - Requires TypeScript 4.5+

3. **Check tsconfig.json**
   ```json
   {
     "compilerOptions": {
       "moduleResolution": "node",
       "esModuleInterop": true
     }
   }
   ```

### Python import errors

**Symptoms:**
- `ModuleNotFoundError: No module named 'hsd_auth'`

**Solutions:**

1. **Install package**
   ```bash
   pip install zalt
   ```

2. **Check virtual environment**
   ```bash
   which python  # Verify correct Python
   pip list | grep hsd  # Verify package installed
   ```

3. **Check Python version**
   - Requires Python 3.9+

### Storage errors

**Symptoms:**
- "localStorage is not defined"
- Tokens not persisting

**Solutions:**

1. **Server-side rendering**
   ```typescript
   // Check if running in browser
   const auth = new HSDAuthClient({
     storage: typeof window !== 'undefined' ? localStorage : undefined
   });
   ```

2. **Custom storage for Node.js**
   ```typescript
   import { MemoryStorage } from '@hsd/auth-sdk';
   
   const auth = new HSDAuthClient({
     storage: new MemoryStorage()
   });
   ```

3. **React Native**
   ```typescript
   import AsyncStorage from '@react-native-async-storage/async-storage';
   
   const auth = new HSDAuthClient({
     storage: AsyncStorage
   });
   ```

## Dashboard Issues

### Can't login to dashboard

**Symptoms:**
- Dashboard login fails
- Redirected back to login page

**Solutions:**

1. **Check admin account exists**
   - Contact super admin to verify account

2. **Check role permissions**
   - Account may not have dashboard access

3. **Clear cookies**
   - Clear browser cookies for dashboard domain

4. **Check browser console**
   - Look for specific error messages

### Missing data in dashboard

**Symptoms:**
- Realms/users not showing
- Empty lists

**Solutions:**

1. **Check permissions**
   - Your role may not have access to all realms

2. **Check realm access**
   - Non-super-admins only see assigned realms

3. **Refresh data**
   - Try refreshing the page

4. **Check API connection**
   - Browser console → Network tab → Check API calls

### Slow dashboard performance

**Symptoms:**
- Pages load slowly
- UI feels sluggish

**Solutions:**

1. **Check network**
   - Slow internet affects API calls

2. **Reduce data**
   - Use filters to reduce data loaded

3. **Clear browser cache**
   - Old cached data may cause issues

## AWS/Infrastructure Issues

### Lambda timeout

**Symptoms:**
- API returns 504 Gateway Timeout
- Requests take too long

**Solutions:**

1. **Check Lambda logs**
   ```bash
   aws logs tail /aws/lambda/zalt-login --follow
   ```

2. **Increase timeout**
   - SAM template → Function → Timeout

3. **Check DynamoDB**
   - May be throttled
   - Check CloudWatch metrics

### DynamoDB throttling

**Symptoms:**
- Intermittent 500 errors
- "ProvisionedThroughputExceededException"

**Solutions:**

1. **Check capacity**
   ```bash
   aws cloudwatch get-metric-statistics \
     --namespace AWS/DynamoDB \
     --metric-name ThrottledRequests \
     --dimensions Name=TableName,Value=zalt-users \
     --start-time 2024-01-01T00:00:00Z \
     --end-time 2024-01-02T00:00:00Z \
     --period 3600 \
     --statistics Sum
   ```

2. **Switch to on-demand**
   ```bash
   aws dynamodb update-table \
     --table-name zalt-users \
     --billing-mode PAY_PER_REQUEST
   ```

3. **Enable auto-scaling**
   - Configure in AWS Console

### Secrets Manager errors

**Symptoms:**
- "Unable to retrieve secret"
- JWT signing fails

**Solutions:**

1. **Check secret exists**
   ```bash
   aws secretsmanager describe-secret \
     --secret-id zalt/jwt-secrets
   ```

2. **Check Lambda IAM role**
   - Must have `secretsmanager:GetSecretValue` permission

3. **Check region**
   - Secret must be in same region as Lambda

## Debugging Tips

### Enable debug logging

**JavaScript SDK:**
```typescript
const auth = new HSDAuthClient({
  debug: true // Enables console logging
});
```

**Python SDK:**
```python
import logging
logging.basicConfig(level=logging.DEBUG)

auth = HSDAuthClient(debug=True)
```

### Check request/response

**Browser:**
1. Open DevTools (F12)
2. Go to Network tab
3. Filter by "api.auth"
4. Click request to see details

**cURL:**
```bash
curl -v -X POST https://api.auth.hsdcore.com/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test","realm_id":"realm-123"}'
```

### Check CloudWatch logs

```bash
# Lambda logs
aws logs tail /aws/lambda/zalt-login --follow

# API Gateway logs
aws logs tail /aws/apigateway/zalt-api --follow
```

## Getting Help

1. **Check documentation**
   - [API Reference](api-reference.md)
   - [SDK Guide](sdk-integration-guide.md)

2. **Search issues**
   - GitHub issues may have solutions

3. **Contact support**
   - Email: support@hsdcore.com
   - Slack: #zalt-support

4. **Emergency**
   - On-call: +49-xxx-xxx-xxxx
