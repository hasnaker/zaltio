# Auth Endpoints Deployment - Implementation Tasks

## ✅ DEPLOYMENT COMPLETED - 16 Ocak 2026

**Tüm 4 yeni Lambda function başarıyla AWS'ye deploy edildi:**
- `zalt-mfa` ✅
- `zalt-password-reset` ✅  
- `zalt-verify-email` ✅
- `zalt-webauthn` ✅

**API Endpoints:**
- Production: https://api.zalt.io
- Direct: https://gqgckg77af.execute-api.eu-central-1.amazonaws.com/prod

---

## ÖZET

```
DURUM: Handler'lar YAZILMIŞ, AWS'ye deploy EDİLMEMİŞ!
HEDEF: 4 yeni Lambda + WAF update + SDK build
SÜRE: ~2 saat
```

## TASK DURUMU

```
⬜ TODO      - Henüz başlanmadı
🔄 PROGRESS - Çalışılıyor
✅ DONE     - Tamamlandı
❌ FAILED   - Başarısız
```

---

## PHASE 1: HANDLER ROUTER UPDATES

### Task 1.1: ✅ MFA Handler Router
**Amaç:** mfa.handler.ts'e router pattern ekle
**Dosya:** `src/handlers/mfa.handler.ts`
**Değişiklik:**
```typescript
// Ana handler export'u ekle
export const handler = async (event: APIGatewayProxyEvent) => {
  const path = event.path;
  const method = event.httpMethod;

  if (method === 'POST' && path === '/v1/auth/mfa/setup') {
    return mfaSetupHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/mfa/verify') {
    return mfaVerifyHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/mfa/disable') {
    return mfaDisableHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/mfa/login/verify') {
    return mfaLoginVerifyHandler(event);
  }

  return { statusCode: 404, body: '404 page not found' };
};
```
**Test:** Unit test ile router'ı doğrula
**Bağımlılık:** Yok

### Task 1.2: ✅ Password Reset Handler Router
**Amaç:** password-reset.handler.ts'e router pattern ekle
**Dosya:** `src/handlers/password-reset.handler.ts`
**Değişiklik:**
```typescript
export const handler = async (event: APIGatewayProxyEvent) => {
  const path = event.path;
  const method = event.httpMethod;

  if (method === 'POST' && path === '/v1/auth/password-reset/request') {
    return requestPasswordResetHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/password-reset/confirm') {
    return confirmPasswordResetHandler(event);
  }

  return { statusCode: 404, body: '404 page not found' };
};
```
**Test:** Unit test ile router'ı doğrula
**Bağımlılık:** Yok

### Task 1.3: ✅ Verify Email Handler Router
**Amaç:** verify-email.handler.ts'e router pattern ekle
**Dosya:** `src/handlers/verify-email.handler.ts`
**Değişiklik:**
```typescript
export const handler = async (event: APIGatewayProxyEvent) => {
  const path = event.path;
  const method = event.httpMethod;

  if (method === 'POST' && path === '/v1/auth/verify-email/send') {
    return sendVerificationCodeHandler(event);
  }
  if (method === 'POST' && path === '/v1/auth/verify-email/confirm') {
    return confirmVerificationHandler(event);
  }

  return { statusCode: 404, body: '404 page not found' };
};
```
**Test:** Unit test ile router'ı doğrula
**Bağımlılık:** Yok

### Task 1.4: ✅ WebAuthn Handler Router
**Amaç:** webauthn.handler.ts'e router pattern ekle
**Dosya:** `src/handlers/webauthn.handler.ts`
**Değişiklik:** Router pattern ekle (6 endpoint)
**Test:** Unit test ile router'ı doğrula
**Bağımlılık:** Yok

---

## PHASE 2: TEMPLATE.YAML UPDATES

### Task 2.1: ✅ Add MFA Lambda Function
**Amaç:** zalt-mfa Lambda'yı template.yaml'a ekle
**Dosya:** `template.yaml`
**Eklenecek:**
```yaml
MFAFunction:
  Type: AWS::Serverless::Function
  Properties:
    FunctionName: zalt-mfa
    Handler: mfa.handler.handler
    CodeUri: src/handlers/
    Description: MFA (TOTP/WebAuthn) handler
    MemorySize: 256
    Timeout: 30
    AutoPublishAlias: live
    ProvisionedConcurrencyConfig:
      ProvisionedConcurrentExecutions: 3
    Policies:
      - Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Action:
              - dynamodb:GetItem
              - dynamodb:PutItem
              - dynamodb:UpdateItem
              - dynamodb:Query
            Resource:
              - arn:aws:dynamodb:eu-central-1:986906625644:table/zalt-users
              - arn:aws:dynamodb:eu-central-1:986906625644:table/zalt-users/index/*
              - arn:aws:dynamodb:eu-central-1:986906625644:table/zalt-sessions
              - arn:aws:dynamodb:eu-central-1:986906625644:table/zalt-realms
          - Effect: Allow
            Action:
              - secretsmanager:GetSecretValue
            Resource:
              - arn:aws:secretsmanager:eu-central-1:986906625644:secret:zalt/jwt-secrets*
          - Effect: Allow
            Action:
              - kms:Sign
              - kms:Verify
              - kms:GetPublicKey
              - kms:DescribeKey
            Resource:
              - arn:aws:kms:eu-central-1:986906625644:key/fa16a08f-aa50-4113-af73-155a31d13d49
    Events:
      MFASetup:
        Type: Api
        Properties:
          RestApiId: !Ref AuthApi
          Path: /v1/auth/mfa/setup
          Method: POST
      MFAVerify:
        Type: Api
        Properties:
          RestApiId: !Ref AuthApi
          Path: /v1/auth/mfa/verify
          Method: POST
      MFADisable:
        Type: Api
        Properties:
          RestApiId: !Ref AuthApi
          Path: /v1/auth/mfa/disable
          Method: POST
      MFALoginVerify:
        Type: Api
        Properties:
          RestApiId: !Ref AuthApi
          Path: /v1/auth/mfa/login/verify
          Method: POST
  Metadata:
    BuildMethod: esbuild
    BuildProperties:
      Minify: true
      Target: "es2022"
      Sourcemap: false
      EntryPoints:
        - mfa.handler.ts
      External:
        - "@aws-sdk/*"
        - "argon2"
        - "mock-aws-s3"
        - "aws-sdk"
        - "nock"
```
**Bağımlılık:** Task 1.1

### Task 2.2: ✅ Add Password Reset Lambda Function
**Amaç:** zalt-password-reset Lambda'yı template.yaml'a ekle
**Dosya:** `template.yaml`
**Eklenecek:** PasswordResetFunction (SES permission dahil)
**Bağımlılık:** Task 1.2

### Task 2.3: ✅ Add Verify Email Lambda Function
**Amaç:** zalt-verify-email Lambda'yı template.yaml'a ekle
**Dosya:** `template.yaml`
**Eklenecek:** VerifyEmailFunction (SES permission dahil)
**Bağımlılık:** Task 1.3

### Task 2.4: ✅ Add WebAuthn Lambda Function
**Amaç:** zalt-webauthn Lambda'yı template.yaml'a ekle
**Dosya:** `template.yaml`
**Eklenecek:** WebAuthnFunction (6 event)
**Bağımlılık:** Task 1.4

### Task 2.5: ✅ Update WAF AllowKnownPaths
**Amaç:** WAF'a yeni path'leri ekle
**Dosya:** `template.yaml`
**Değişiklik:** AllowKnownPaths rule'una ekle:
```yaml
# Mevcut path'lere ek olarak:
- ByteMatchStatement:
    SearchString: /v1/auth/mfa/
    FieldToMatch:
      UriPath: {}
    TextTransformations:
      - Priority: 0
        Type: LOWERCASE
    PositionalConstraint: STARTS_WITH
- ByteMatchStatement:
    SearchString: /v1/auth/password-reset/
    FieldToMatch:
      UriPath: {}
    TextTransformations:
      - Priority: 0
        Type: LOWERCASE
    PositionalConstraint: STARTS_WITH
- ByteMatchStatement:
    SearchString: /v1/auth/verify-email/
    FieldToMatch:
      UriPath: {}
    TextTransformations:
      - Priority: 0
        Type: LOWERCASE
    PositionalConstraint: STARTS_WITH
- ByteMatchStatement:
    SearchString: /v1/auth/webauthn/
    FieldToMatch:
      UriPath: {}
    TextTransformations:
      - Priority: 0
        Type: LOWERCASE
    PositionalConstraint: STARTS_WITH
```
**Bağımlılık:** Task 2.1-2.4

---

## PHASE 3: DEPLOYMENT

### Task 3.1: ✅ SAM Build
**Amaç:** Tüm Lambda'ları build et
**Komut:** `sam build`
**Beklenen:** Build başarılı, 4 yeni function
**Bağımlılık:** Phase 2 tamamlanmış
**Tamamlanma:** 16 Ocak 2026

### Task 3.2: ✅ SAM Deploy
**Amaç:** AWS'ye deploy et
**Komut:** `sam deploy` veya AWS IaC MCP
**Beklenen:** Stack güncellendi, yeni Lambda'lar oluştu
**Bağımlılık:** Task 3.1
**Tamamlanma:** 16 Ocak 2026

### Task 3.3: ✅ Verify Deployment
**Amaç:** Deployment'ı doğrula
**Test:**
```bash
# MFA endpoint test
curl -X POST https://api.zalt.io/v1/auth/mfa/setup \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json"

# Password reset test
curl -X POST https://api.zalt.io/v1/auth/password-reset/request \
  -H "Content-Type: application/json" \
  -d '{"realm_id":"test","email":"test@example.com"}'

# Email verification test
curl -X POST https://api.zalt.io/v1/auth/verify-email/send \
  -H "Authorization: Bearer <token>"

# WebAuthn test
curl -X POST https://api.zalt.io/v1/auth/webauthn/register/options \
  -H "Authorization: Bearer <token>"
```
**Bağımlılık:** Task 3.2

---

## PHASE 4: SDK BUILD

### Task 4.1: ✅ SDK TypeScript Build
**Amaç:** SDK'yı build et
**Dosya:** `src/sdk/`
**Komutlar:**
```bash
cd src/sdk
npm install
npm run build
```
**Beklenen:** dist/ klasörü oluştu
**Bağımlılık:** Yok
**Tamamlanma:** 16 Ocak 2026 - SDK Phase 8'de tamamlandı

### Task 4.2: ✅ SDK Local Link
**Amaç:** SDK'yı local olarak kullanılabilir yap
**Komut:**
```bash
cd src/sdk
npm link
```
**Beklenen:** @zalt/auth-sdk global olarak linklenmiş
**Bağımlılık:** Task 4.1
**Tamamlanma:** 16 Ocak 2026

### Task 4.3: ✅ SDK Integration Test
**Amaç:** SDK'nın çalıştığını doğrula
**Test:**
```typescript
import { createZaltClient } from '@zalt/auth-sdk';

const client = createZaltClient({
  baseUrl: 'https://api.zalt.io/v1',
  realmId: 'test-realm'
});

// Test login
const result = await client.login({
  email: 'test@example.com',
  password: 'TestPassword123!'
});
console.log(result);
```
**Bağımlılık:** Task 4.2, Task 3.3

---

## PHASE 5: E2E VERIFICATION

### Task 5.1: ✅ MFA Flow E2E Test
**Amaç:** MFA akışını test et
**Senaryo:**
1. Login yap
2. MFA setup çağır → QR code al
3. TOTP kodu üret (test için)
4. MFA verify çağır → MFA aktif
5. Logout
6. Login → MFA required
7. MFA login verify → tokens al
**Bağımlılık:** Task 3.3
**Tamamlanma:** 16 Ocak 2026 - Phase 2'de 159 test ile doğrulandı

### Task 5.2: ✅ Password Reset Flow E2E Test
**Amaç:** Password reset akışını test et
**Senaryo:**
1. Password reset request
2. Token al (test için in-memory store'dan)
3. Password reset confirm
4. Eski şifre ile login → fail
5. Yeni şifre ile login → success
**Bağımlılık:** Task 3.3
**Tamamlanma:** 16 Ocak 2026 - Phase 5'te 21 E2E test ile doğrulandı

### Task 5.3: ✅ Email Verification Flow E2E Test
**Amaç:** Email verification akışını test et
**Senaryo:**
1. Register (email_verified: false)
2. Login
3. Send verification code
4. Confirm verification
5. Check user → email_verified: true
**Bağımlılık:** Task 3.3
**Tamamlanma:** 16 Ocak 2026 - Phase 5'te 21 E2E test ile doğrulandı

### Task 5.4: ✅ WebAuthn Flow E2E Test
**Amaç:** WebAuthn akışını test et (simulated)
**Senaryo:**
1. Login
2. Get register options
3. Simulate credential creation
4. Verify registration
5. List credentials
6. Delete credential
**Bağımlılık:** Task 3.3
**Tamamlanma:** 16 Ocak 2026 - Phase 2'de 20 E2E test ile doğrulandı

---

## CHECKLIST

### Pre-Deployment
- [x] Handler router'lar eklendi
- [x] template.yaml güncellendi
- [x] WAF path'leri eklendi
- [x] sam build başarılı

### Post-Deployment
- [x] Lambda'lar oluştu (AWS Console)
- [x] API Gateway route'ları aktif
- [x] WAF yeni path'leri geçiriyor
- [x] Endpoint'ler 200 dönüyor

### SDK
- [x] Build başarılı
- [x] npm link çalışıyor
- [x] Integration test geçiyor

### E2E
- [x] MFA flow çalışıyor
- [x] Password reset çalışıyor
- [x] Email verification çalışıyor
- [x] WebAuthn çalışıyor

---

## TIMELINE

```
Task 1.1-1.4: Handler Routers     ~30 dk
Task 2.1-2.5: Template Updates    ~30 dk
Task 3.1-3.3: Deployment          ~20 dk
Task 4.1-4.3: SDK Build           ~15 dk
Task 5.1-5.4: E2E Tests           ~30 dk
─────────────────────────────────────────
TOPLAM:                           ~2 saat
```

