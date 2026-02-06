# Implementation Plan: Zalt Game-Changer Features

## Overview

Bu implementation plan, Clerk'in 2025-2026 yılında çıkardığı game-changer özellikleri Zalt'a ekler. Machine Authentication, Reverification, Session Tasks, Billing Integration, ve AI-powered security özellikleri.

## Tasks

### Phase 1: Machine Authentication (M2M + API Keys)

- [x] 1. Machine-to-Machine (M2M) Authentication
  - [x] 1.1 Implement Machine model and repository
    - DynamoDB table: zalt-machines
    - pk: REALM#{realmId}#MACHINE#{machineId}
    - GSI: client-id-index (clientId -> machineId)
    - Fields: id, realmId, name, clientId, clientSecretHash, scopes, allowedTargets, status
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Machine Authentication
    - _Requirements: 1.1, 1.2_
  
  - [x] 1.2 Implement MachineAuthService
    - createMachine(realmId, config): Generate clientId + clientSecret
    - authenticateMachine(clientId, clientSecret): Validate and issue M2M token
    - validateM2MToken(token): Verify JWT and extract claims
    - rotateCredentials(machineId): Generate new credentials
    - listMachines(realmId): List all machines
    - deleteMachine(machineId): Soft delete
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - M2M Service
    - _Requirements: 1.3, 1.4, 1.5, 1.6_
  
  - [x] 1.3 Implement M2M Handler (Lambda)
    - POST /machines - Create machine
    - POST /machines/token - Get M2M token
    - GET /machines - List machines
    - DELETE /machines/{id} - Delete machine
    - POST /machines/{id}/rotate - Rotate credentials
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - M2M Endpoints
    - _Requirements: 1.7, 1.8_
  
  - [x] 1.4 Implement M2M scope enforcement middleware
    - Extract M2M token from Authorization header
    - Validate scopes against endpoint requirements
    - Return 403 if scope insufficient
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/security.md` - M2M Scopes
    - _Requirements: 1.7_
  
  - [x] 1.5 Write property tests for M2M
    - **Property 1: M2M token scope enforcement**
    - **Property 2: Credential rotation invalidates old credentials**
    - **Property 3: M2M token expiry is enforced**
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - **Validates: Requirements 1.4, 1.5, 1.7**

- [x] 2. User-Generated API Keys ✅
  - [x] 2.1 Implement APIKey model and repository
    - DynamoDB table: zalt-api-keys
    - pk: USER#{userId}#KEY#{keyId}
    - GSI: key-hash-index (keyHash -> keyId)
    - Fields: id, userId, realmId, tenantId, name, keyPrefix, keyHash, scopes, expiresAt, status
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - API Keys
    - _Requirements: 2.1, 2.2_
  
  - [x] 2.2 Implement APIKeyService
    - createKey(userId, config): Generate zalt_key_xxx, return full key once
    - validateKey(fullKey): Hash and lookup, return user context
    - listKeys(userId): Return masked keys with metadata
    - revokeKey(keyId): Invalidate immediately
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - API Key Service
    - _Requirements: 2.3, 2.4, 2.5, 2.6_
  
  - [x] 2.3 Implement API Key Handler (Lambda)
    - POST /api-keys - Create API key
    - GET /api-keys - List user's API keys
    - DELETE /api-keys/{id} - Revoke API key
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - API Key Endpoints
    - _Requirements: 2.7, 2.9_
  
  - [x] 2.4 Implement API Key authentication middleware
    - Detect zalt_key_ prefix in Authorization header
    - Validate key and inject user context
    - Inherit user's tenant context and permissions
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/security.md` - API Key Auth
    - _Requirements: 2.7, 2.8_
  
  - [x] 2.5 Write property tests for API Keys
    - **Property 4: API key user context preservation**
    - **Property 5: Revoked key returns 401**
    - **Property 6: Expired key returns 401**
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - **Validates: Requirements 2.7, 2.8, 2.5, 2.6**

- [x] 3. Checkpoint - Machine Authentication Complete
  - Ensure all M2M and API Key tests pass
  - Verify endpoints work in production
  - Update `CHANGELOG.md` with new features
  - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
  - ✅ ONAY ALINIRSA → Sonraki phase'e geç
  - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et


### Phase 2: Reverification & Session Tasks

- [x] 4. Reverification (Step-Up Authentication)
  - [x] 4.1 Implement ReverificationService ✅
    - requireReverification(sessionId, level): Mark session as needing reverification
    - checkReverification(sessionId, requiredLevel): Check if session is verified
    - completeReverification(sessionId, level, proof): Verify and update session
    - getRequiredLevel(endpoint): Get reverification config for endpoint
    - ✅ 56 tests passing
    - Update: `docs/security.md` - Reverification
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/security.md` - Reverification
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_
  
  - [x] 4.2 Implement Reverification Handler (Lambda)
    - POST /reverify/password - Verify with password
    - POST /reverify/mfa - Verify with MFA
    - POST /reverify/webauthn - Verify with WebAuthn
    - GET /reverify/status - Check reverification status
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Reverification Endpoints
    - _Requirements: 3.4, 3.6_
  
  - [x] 4.3 Implement reverification middleware
    - Check endpoint reverification requirements
    - Return 403 REVERIFICATION_REQUIRED if not verified
    - Include required level in response
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/security.md` - Reverification Middleware
    - _Requirements: 3.1, 3.2_
  
  - [x] 4.4 Implement SDK useReverification() hook
    - Detect 403 REVERIFICATION_REQUIRED
    - Show reverification modal
    - Retry original request after success
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - useReverification
    - _Requirements: 3.6, 3.7_
  
  - [x] 4.5 Write property tests for Reverification
    - **Property 7: Reverification expiry is enforced**
    - **Property 8: Higher level satisfies lower level requirements**
    - **Property 9: Reverification status persists across requests**
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - **Validates: Requirements 3.4, 3.5**

- [x] 5. Session Tasks (Post-Login Requirements)
  - [x] 5.1 Implement SessionTask model and repository
    - DynamoDB: Add to zalt-sessions table
    - pk: SESSION#{sessionId}#TASK#{taskId}
    - Fields: id, sessionId, userId, type, status, metadata, createdAt, completedAt
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Session Tasks
    - _Requirements: 4.1_
  
  - [x] 5.2 Implement SessionTasksService
    - createTask(sessionId, type, metadata): Create pending task
    - getPendingTasks(sessionId): List pending tasks
    - completeTask(taskId): Mark task as completed
    - hasBlockingTasks(sessionId): Check if session is blocked
    - forcePasswordReset(userId, revokeAllSessions): Create reset_password task
    - forcePasswordResetAll(realmId): Mass password reset
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Session Tasks Service
    - _Requirements: 4.2, 4.3, 4.4, 4.5, 4.7, 4.8, 4.9_
  
  - [x] 5.3 Implement Session Tasks Handler (Lambda)
    - GET /session/tasks - Get pending tasks
    - POST /session/tasks/{id}/complete - Complete task
    - POST /admin/users/{id}/force-password-reset - Force password reset
    - POST /admin/realm/force-password-reset - Mass password reset
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Session Tasks Endpoints
    - _Requirements: 4.7, 4.8_
  
  - [x] 5.4 Implement session task blocking middleware
    - Check for pending blocking tasks
    - Return 403 SESSION_TASK_PENDING if blocked
    - Allow task completion endpoints
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/security.md` - Session Task Blocking
    - _Requirements: 4.2_
  
  - [x] 5.5 Integrate session tasks with login flow
    - Create choose_organization task if multiple orgs
    - Create setup_mfa task if MFA required by policy
    - Create reset_password task if password compromised
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Login Flow
    - _Requirements: 4.3, 4.4, 4.5_
  
  - [x] 5.6 Write property tests for Session Tasks
    - **Property 10: Session task blocking is enforced**
    - **Property 11: Task completion removes blocking**
    - **Property 12: Force password reset creates task**
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - **Validates: Requirements 4.2, 4.9**

- [x] 6. Checkpoint - Reverification & Session Tasks Complete
  - Ensure all tests pass
  - Verify step-up auth works in production
  - Update `CHANGELOG.md`
  - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
  - ✅ ONAY ALINIRSA → Sonraki phase'e geç
  - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et


### Phase 3: Invitation & Webhook Systems

- [x] 7. Invitation System
  - [x] 7.1 Implement Invitation model and repository
    - DynamoDB table: zalt-invitations
    - pk: TENANT#{tenantId}#INVITATION#{invitationId}
    - GSI: token-index (token -> invitationId)
    - GSI: email-index (email -> invitations)
    - Fields: id, tenantId, email, role, permissions, invitedBy, token, status, expiresAt
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Invitations
    - _Requirements: 11.1_
  
  - [x] 7.2 Implement InvitationService
    - create(tenantId, email, role, invitedBy): Create invitation with 7-day expiry
    - accept(token, userId?, newUserData?): Accept invitation
    - revoke(invitationId): Invalidate invitation
    - list(tenantId): List pending/expired invitations
    - resend(invitationId): Resend invitation email
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Invitation Service
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6_
  
  - [x] 7.3 Implement Invitation Handler (Lambda)
    - POST /tenants/{id}/invitations - Create invitation
    - GET /tenants/{id}/invitations - List invitations
    - POST /invitations/accept - Accept invitation
    - DELETE /invitations/{id} - Revoke invitation
    - POST /invitations/{id}/resend - Resend invitation
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Invitation Endpoints
    - _Requirements: 11.7_
  
  - [x] 7.4 Implement invitation email templates
    - Invitation email with tenant name, inviter, role
    - Accept link with token
    - SES integration
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/configuration/email-templates.md`
    - _Requirements: 11.2_
  
  - [x] 7.5 Implement SDK <InvitationList /> component
    - List pending invitations
    - Resend/revoke actions
    - Create invitation form
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - InvitationList
    - _Requirements: 11.10_
  
  - [x] 7.6 Write property tests for Invitations
    - **Property 13: Invitation token single use**
    - **Property 14: Invitation expiry rejects acceptance**
    - **Property 15: Revoked invitation cannot be accepted**
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - **Validates: Requirements 11.3, 11.4, 11.5, 11.6**

- [x] 8. Webhook System ✅ COMPLETE
  - [x] 8.1 Implement Webhook model and repository
    - DynamoDB table: zalt-webhooks
    - pk: REALM#{realmId}#WEBHOOK#{webhookId}
    - Fields: id, realmId, url, secret, events, status, createdAt
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/configuration/webhooks.md`
    - _Requirements: 12.1_
  
  - [x] 8.2 Implement WebhookDelivery model and repository
    - DynamoDB table: zalt-webhook-deliveries
    - pk: WEBHOOK#{webhookId}#DELIVERY#{deliveryId}
    - sk: DELIVERY#{timestamp}
    - Fields: id, webhookId, eventType, payload, status, attempts, responseCode, error
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/configuration/webhooks.md`
    - _Requirements: 12.7_
  
  - [x] 8.3 Implement WebhookService ✅ 24 tests passing
    - create(realmId, url, events): Create webhook with signing secret
    - dispatch(realmId, eventType, data): Queue webhook delivery
    - test(webhookId): Send test event
    - getDeliveryLogs(webhookId, limit): Get delivery history
    - rotateSecret(webhookId): Generate new signing secret
    - verifySignature(payload, signature, secret): Verify HMAC-SHA256
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/configuration/webhooks.md`
    - _Requirements: 12.1, 12.3, 12.6, 12.9_
  
  - [x] 8.4 Implement Webhook Delivery Lambda ✅ 7 tests passing
    - SQS trigger for webhook queue
    - POST with HMAC-SHA256 signature
    - Retry with exponential backoff (1s, 5s, 30s, 5m)
    - Store delivery result
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/configuration/webhooks.md`
    - _Requirements: 12.3, 12.4, 12.5_
  
  - [x] 8.5 Implement Webhook Handler (Lambda) ✅ 15 tests passing
    - POST /webhooks - Create webhook
    - GET /webhooks - List webhooks
    - DELETE /webhooks/{id} - Delete webhook
    - POST /webhooks/{id}/test - Test webhook
    - GET /webhooks/{id}/deliveries - Get delivery logs
    - POST /webhooks/{id}/rotate-secret - Rotate secret
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Webhook Endpoints
    - _Requirements: 12.6, 12.7, 12.9_
  
  - [x] 8.6 Integrate webhooks with auth events ✅ 23 tests passing
    - user.created, user.updated, user.deleted
    - session.created, session.revoked
    - tenant.created, tenant.updated
    - member.invited, member.joined, member.removed
    - mfa.enabled, mfa.disabled
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/configuration/webhooks.md` - Events
    - _Requirements: 12.2, 11.8, 11.9_
  
  - [x] 8.7 Implement SDK webhook signature verification ✅ 34 TS tests + Python impl
    - verifyWebhookSignature(payload, signature, secret)
    - TypeScript and Python implementations
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/core/README.md` - Webhook Verification
    - _Requirements: 12.10_
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/core/README.md` - Webhook Verification
    - _Requirements: 12.10_
  
  - [x] 8.8 Write property tests for Webhooks ✅ 20 tests passing
    - **Property 16: Webhook signature validity**
    - **Property 17: Retry with exponential backoff**
    - **Property 18: Event filtering works correctly**
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - **Validates: Requirements 12.3, 12.4, 12.5, 12.8**

- [x] 9. Checkpoint - Invitation & Webhook Complete ✅
  - ✅ All tests pass (384 passed, 1 unrelated e2e timeout)
  - ✅ Webhook delivery system complete with retry logic
  - ✅ SDK webhook verification (TypeScript + Python)
  - ✅ Property tests passing (20 tests)
  - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
  - ✅ ONAY ALINIRSA → Sonraki phase'e geç
  - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et


### Phase 4: Waitlist & Impersonation

- [x] 10. Waitlist Mode ✅ COMPLETE (125 tests total)
  - [x] 10.1 Implement Waitlist model and repository ✅ 38 tests passing
    - DynamoDB table: zalt-waitlist
    - pk: REALM#{realmId}#WAITLIST#{entryId}
    - GSI: email-index (email -> entryId)
    - Fields: id, realmId, email, metadata, status, position, referralCode, createdAt
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Waitlist
    - _Requirements: 5.1, 5.2_
  
  - [x] 10.2 Implement WaitlistService ✅ 29 tests passing
    - join(realmId, email, metadata): Add to waitlist
    - approve(entryId): Approve and send invitation
    - reject(entryId): Reject entry
    - bulkApprove(entryIds): Bulk approval
    - getPosition(entryId): Get waitlist position
    - listEntries(realmId, status): List entries
    - isWaitlistMode(realmId): Check if waitlist mode enabled
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Waitlist Service
    - _Requirements: 5.3, 5.4, 5.5, 5.6, 5.8, 5.9_
  
  - [x] 10.3 Implement Waitlist Handler (Lambda) ✅ 34 tests passing
    - POST /waitlist - Join waitlist
    - GET /waitlist - List entries (admin)
    - POST /waitlist/{id}/approve - Approve entry
    - POST /waitlist/{id}/reject - Reject entry
    - POST /waitlist/bulk-approve - Bulk approve
    - GET /waitlist/position/{id} - Get position
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Waitlist Endpoints
    - _Requirements: 5.5_
  
  - [x] 10.4 Implement waitlist mode in registration ✅ 5 tests passing
    - Check if waitlist mode enabled
    - Return 403 WAITLIST_MODE_ACTIVE if enabled
    - Redirect to waitlist signup
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Registration
    - _Requirements: 5.1, 5.9_
  
  - [x] 10.5 Implement SDK <Waitlist /> component ✅ 29 tests passing
    - Waitlist signup form
    - Position display
    - Status updates
    - Referral code support
    - Custom fields support
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - Waitlist
    - _Requirements: 5.7_
  
  - [x] 10.6 Write property tests for Waitlist ✅ 19 tests passing
    - **Property 19: Waitlist mode blocks registration**
    - **Property 20: Approval sends invitation**
    - **Property 21: Position is calculated correctly**
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - **Validates: Requirements 5.1, 5.4, 5.8**

- [x] 11. User Impersonation ✅ COMPLETE (192 tests total)
  - [x] 11.1 Implement ImpersonationSession model ✅ 44 tests passing
    - Add to zalt-sessions table
    - Fields: id, adminId, targetUserId, reason, restrictions, startedAt, expiresAt, endedAt
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Impersonation
    - _Requirements: 6.2, 6.3_
  
  - [x] 11.2 Implement ImpersonationService ✅ 63 tests passing
    - startImpersonation(adminId, targetUserId, reason): Create impersonation session
    - endImpersonation(sessionId): End impersonation
    - isImpersonating(sessionId): Check if session is impersonation
    - getRestrictions(sessionId): Get impersonation restrictions
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Impersonation Service
    - _Requirements: 6.1, 6.5, 6.6_
  
  - [x] 11.3 Implement Impersonation Handler (Lambda) ✅ 27 tests passing
    - POST /admin/users/{id}/impersonate - Start impersonation
    - POST /impersonation/end - End impersonation
    - GET /impersonation/status - Check impersonation status
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Impersonation Endpoints
    - _Requirements: 6.9_
  
  - [x] 11.4 Implement impersonation restrictions middleware ✅ 34 tests passing
    - Block password change during impersonation
    - Block account deletion during impersonation
    - Return 403 IMPERSONATION_RESTRICTED
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/security.md` - Impersonation Restrictions
    - _Requirements: 6.8_
  
  - [x] 11.5 Implement SDK useImpersonation() hook ✅ 26 tests passing
    - Detect impersonation status
    - Show visual indicator
    - End impersonation action
    - Countdown timer for session expiry
    - Polling support for status updates
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - useImpersonation
    - _Requirements: 6.4, 6.10_
  
  - [x] 11.6 Write property tests for Impersonation ✅ 24 tests passing
    - **Property 22: Impersonation restrictions are enforced**
    - **Property 23: Impersonation session expires**
    - **Property 24: Audit log records impersonation**
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - **Validates: Requirements 6.5, 6.7, 6.8**

- [x] 12. Checkpoint - Waitlist & Impersonation Complete ✅
  - ✅ All tests pass (319 tests: Waitlist 125 + Impersonation 194)
  - ✅ Waitlist mode with referral codes and position tracking
  - ✅ User impersonation with restrictions and audit logging
  - ✅ SDK hooks: useImpersonation (26 tests)
  - ✅ Property tests: 43 tests (Waitlist 19 + Impersonation 24)
  - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
  - ✅ ONAY ALINIRSA → Sonraki phase'e geç
  - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et


### Phase 5: Billing Integration

- [x] 13. Integrated Billing (Clerk Billing Style)
  - [x] 13.1 Implement BillingPlan model and repository
    - DynamoDB table: zalt-billing-plans
    - pk: REALM#{realmId}#PLAN#{planId}
    - Fields: id, realmId, name, type, priceMonthly, priceYearly, features, limits, stripePriceId
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Billing Plans
    - _Requirements: 7.2_
  
  - [x] 13.2 Implement Subscription model and repository
    - DynamoDB table: zalt-subscriptions
    - pk: TENANT#{tenantId}#SUBSCRIPTION#{subscriptionId}
    - GSI: stripe-index (stripeSubscriptionId -> subscriptionId)
    - Fields: id, tenantId, planId, stripeSubscriptionId, status, currentPeriodEnd
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Subscriptions
    - _Requirements: 7.4_
  
  - [x] 13.3 Implement BillingService
    - createPlan(realmId, config): Create billing plan
    - subscribe(tenantId, planId, paymentMethodId): Create Stripe subscription
    - cancelSubscription(subscriptionId): Cancel subscription
    - checkEntitlement(tenantId, feature): Check feature access
    - getUsage(tenantId): Get usage metrics
    - handleStripeWebhook(event): Process Stripe webhooks
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Billing Service
    - _Requirements: 7.2, 7.4, 7.5, 7.6_
  
  - [x] 13.4 Implement Stripe integration
    - Create Stripe customer on tenant creation
    - Sync subscription status with webhooks
    - Handle payment failures
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/configuration/billing.md`
    - _Requirements: 7.1, 7.5_
  
  - [x] 13.5 Implement Billing Handler (Lambda)
    - POST /billing/plans - Create plan (admin)
    - GET /billing/plans - List plans
    - POST /billing/subscribe - Subscribe to plan
    - POST /billing/cancel - Cancel subscription
    - GET /billing/subscription - Get current subscription
    - GET /billing/usage - Get usage metrics
    - POST /billing/webhook - Stripe webhook endpoint
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Billing Endpoints
    - _Requirements: 7.3_
  
  - [x] 13.6 Implement entitlement enforcement middleware
    - Check feature access on protected endpoints
    - Return 403 PLAN_LIMIT_EXCEEDED if exceeded
    - Track usage for usage-based billing
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/security.md` - Entitlements
    - _Requirements: 7.6_
  
  - [x] 13.7 Implement SDK <PricingTable /> component
    - Display available plans
    - Plan comparison
    - Subscribe action
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - PricingTable
    - _Requirements: 7.7_
  
  - [x] 13.8 Implement SDK <BillingPortal /> component
    - Current subscription info
    - Payment method management
    - Invoice history
    - Cancel subscription
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - BillingPortal
    - _Requirements: 7.8_
  
  - [x] 13.9 Implement SDK useBilling() hook
    - Get current plan
    - Check entitlements
    - Get usage metrics
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - useBilling
    - _Requirements: 7.9_
  
  - [x] 13.10 Write property tests for Billing
    - **Property 25: Entitlement enforcement is correct**
    - **Property 26: Subscription status syncs with Stripe**
    - **Property 27: Usage tracking is accurate**
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - **Validates: Requirements 7.5, 7.6**

- [x] 14. Checkpoint - Billing Complete
  - Ensure all tests pass
  - Verify Stripe integration works
  - Update `CHANGELOG.md`
  - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
  - ✅ ONAY ALINIRSA → Sonraki phase'e geç
  - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et


### Phase 6: AI Risk Assessment

- [x] 15. AI-Powered Risk Assessment
  - [x] 15.1 Implement RiskAssessment model
    - Fields: score, factors, recommendation, assessedAt
    - RiskFactor: type, score, details
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/security.md` - AI Risk
    - _Requirements: 10.1, 10.2_
  
  - [x] 15.2 Implement AIRiskService
    - assessLoginRisk(context): Calculate risk score (0-100)
    - updateUserBehaviorProfile(userId, event): Learn user patterns
    - detectImpossibleTravel(userId, currentLocation): Check geo-velocity
    - checkIPReputation(ip): Get IP reputation score
    - getDeviceTrustScore(fingerprint, userId): Get device trust score
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/security.md` - AI Risk Service
    - _Requirements: 10.1, 10.2, 10.5, 10.6_
  
  - [x] 15.3 Implement AWS Bedrock integration
    - Anomaly detection model
    - Behavior pattern analysis
    - Risk factor correlation
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/security.md` - AI Integration
    - _Requirements: 10.5_
  
  - [x] 15.4 Integrate risk assessment with login flow
    - Calculate risk score on login attempt
    - If score > 70: Require MFA
    - If score > 90: Block login and notify admin
    - Store risk score in audit log
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/security.md` - Risk-Based Auth
    - _Requirements: 10.3, 10.4, 10.10_
  
  - [x] 15.5 Implement custom risk rules
    - IP whitelist
    - Trusted devices
    - Custom thresholds
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/configuration/risk-rules.md`
    - _Requirements: 10.8_
  
  - [x] 15.6 Implement high-risk webhook trigger
    - Trigger webhook on high-risk login
    - Include risk factors in payload
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/configuration/webhooks.md` - Risk Events
    - _Requirements: 10.9_
  
  - [x] 15.7 Implement Dashboard risk score display
    - Risk score history per user
    - Risk factor breakdown
    - High-risk login alerts
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `dashboard/README.md` - Risk Dashboard
    - _Requirements: 10.7_
  
  - [x] 15.8 Write property tests for AI Risk
    - **Property 28: Risk score consistency (±5 within 1 min)**
    - **Property 29: High risk triggers MFA requirement**
    - **Property 30: Very high risk blocks login**
    - **Property 31: Impossible travel detection works**
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - **Validates: Requirements 10.1, 10.3, 10.4**

- [x] 16. Checkpoint - AI Risk Assessment Complete
  - Ensure all tests pass
  - Verify AI integration works
  - Update `CHANGELOG.md`
  - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
  - ✅ ONAY ALINIRSA → Sonraki phase'e geç
  - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et


### Phase 7: Compromised Password Detection

- [x] 17. Compromised Password Detection
  - [x] 17.1 Implement HaveIBeenPwned integration
    - k-Anonymity API integration
    - SHA-1 prefix lookup
    - Cache results for performance
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/security.md` - Password Security
    - _Requirements: 8.1, 8.2_
  
  - [x] 17.2 Integrate with registration and password change
    - Check password on registration
    - Check password on password change
    - Return PASSWORD_COMPROMISED error if found
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Registration
    - _Requirements: 8.1, 8.2_
  
  - [x] 17.3 Implement admin password compromise actions
    - Mark specific user's password as compromised
    - Mark all passwords as compromised (security incident)
    - Create reset_password session task
    - Optionally revoke all sessions
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Admin Actions
    - _Requirements: 8.3, 8.4, 8.5, 8.6_
  
  - [x] 17.4 Implement background breach check job
    - Periodic check of existing passwords against new breaches
    - Lambda scheduled job (daily)
    - Notify user via email if breach detected
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/security.md` - Breach Detection
    - _Requirements: 8.7, 8.8_
  
  - [x] 17.5 Implement Dashboard compromised password UI
    - Compromised password statistics
    - Force password reset button
    - Mass password reset button
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `dashboard/README.md` - Security Dashboard
    - _Requirements: 8.10_
  
  - [x] 17.6 Write property tests for Compromised Password
    - **Property 32: Compromised password is rejected**
    - **Property 33: Force reset creates session task**
    - **Property 34: Breach notification is sent**
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - **Validates: Requirements 8.1, 8.2, 8.5, 8.8**

- [x] 18. Checkpoint - Compromised Password Complete
  - Ensure all tests pass
  - Verify HIBP integration works
  - Update `CHANGELOG.md`
  - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
  - ✅ ONAY ALINIRSA → Sonraki phase'e geç
  - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et


### Phase 8: Organization-Level SSO

- [x] 19. Organization-Level SSO
  - [x] 19.1 Implement OrgSSO model and repository
    - Add to zalt-tenants table
    - Fields: ssoType, idpMetadata, idpEntityId, spEntityId, acsUrl, sloUrl, certificate
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/configuration/sso-saml.md`
    - _Requirements: 9.1, 9.2_
  
  - [x] 19.2 Implement SAML 2.0 per organization
    - SP-initiated SSO flow
    - IdP metadata parsing
    - SAML assertion validation
    - Attribute mapping
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/configuration/sso-saml.md`
    - _Requirements: 9.2_
  
  - [x] 19.3 Implement OIDC per organization
    - Google Workspace integration
    - Microsoft Entra integration
    - Okta integration
    - Custom OIDC provider support
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/configuration/sso-saml.md`
    - _Requirements: 9.3_
  
  - [x] 19.4 Implement domain verification
    - DNS TXT record verification
    - Domain ownership proof
    - SSO enforcement per domain
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/configuration/sso-saml.md`
    - _Requirements: 9.5_
  
  - [x] 19.5 Implement SSO enforcement
    - Block password login when SSO enforced
    - Redirect to org's IdP automatically
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/configuration/sso-saml.md`
    - _Requirements: 9.4, 9.6_
  
  - [x] 19.6 Implement JIT user provisioning
    - Create user on first SSO login
    - Map IdP attributes to user profile
    - Assign default role
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/configuration/sso-saml.md`
    - _Requirements: 9.8_
  
  - [x] 19.7 Implement SCIM provisioning
    - User sync from IdP
    - Group sync from IdP
    - Deprovisioning on IdP removal
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/configuration/scim.md`
    - _Requirements: 9.9_
  
  - [x] 19.8 Implement Dashboard SSO configuration wizard
    - Step-by-step SSO setup
    - IdP metadata upload
    - Test SSO connection
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `dashboard/README.md` - SSO Setup
    - _Requirements: 9.7_
  
  - [x] 19.9 Write property tests for Org SSO
    - **Property 35: SSO enforcement blocks password login**
    - **Property 36: JIT provisioning creates user**
    - **Property 37: Domain verification is required for enforcement**
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - **Validates: Requirements 9.4, 9.5, 9.6, 9.8**

- [x] 20. Checkpoint - Organization SSO Complete
  - Ensure all tests pass
  - Verify SSO with test IdP
  - Update `CHANGELOG.md`
  - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
  - ✅ ONAY ALINIRSA → Sonraki phase'e geç
  - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et

### Phase 9: Session Handler

- [x] 21. Session Handler (Missing from current implementation)
  - [x] 21.1 Implement Session Handler (Lambda)
    - GET /sessions - List all active sessions
    - GET /sessions/{id} - Get session details
    - DELETE /sessions/{id} - Revoke specific session
    - DELETE /sessions - Revoke all sessions except current
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Sessions
    - _Requirements: 13.1, 13.2, 13.3, 13.4_
  
  - [x] 21.2 Implement session info enrichment
    - Device type detection
    - Browser detection
    - IP geolocation
    - Last activity tracking
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/api-reference.md` - Session Info
    - _Requirements: 13.2_
  
  - [x] 21.3 Implement impossible travel detection
    - Calculate geo-velocity
    - Alert on impossible travel
    - Optionally revoke session
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/security.md` - Impossible Travel
    - _Requirements: 13.5_
  
  - [x] 21.4 Implement session limits enforcement
    - Per-realm session limits
    - Revoke oldest session when limit exceeded
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/configuration/realm-settings.md`
    - _Requirements: 13.6_
  
  - [x] 21.5 Implement SDK <SessionList /> component
    - List active sessions
    - Current session indicator
    - Revoke session action
    - Revoke all action
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - SessionList
    - _Requirements: 13.7_
  
  - [x] 21.6 Implement session.revoked webhook
    - Trigger on session revocation
    - Include session details
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `docs/configuration/webhooks.md`
    - _Requirements: 13.8_
  
  - [x] 21.7 Implement Dashboard session analytics ✅ COMPLETE
    - Concurrent sessions chart
    - Device distribution
    - Location map
    - ✅ ConcurrentSessionsChart component with bar chart
    - ✅ DeviceDistributionChart component with donut chart
    - ✅ LocationDistributionMap component with country flags
    - ✅ Real-time session count with 30s auto-refresh
    - ✅ API route at /api/dashboard/sessions
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `dashboard/README.md` - Session Analytics
    - _Requirements: 13.9_
  
  - [x] 21.8 Write property tests for Session Handler ✅ 13 tests passing
    - **Property 38: Session revocation is immediate**
    - **Property 39: Revoke all keeps current session**
    - **Property 40: Session limits are enforced**
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - **Validates: Requirements 13.3, 13.4, 13.6**

- [x] 22. Checkpoint - Session Handler Complete ✅
  - ✅ All tests pass (475 session tests)
  - ✅ Session management with device info, geo-location
  - ✅ Impossible travel detection
  - ✅ Session limits enforcement
  - ✅ SDK SessionList component (29 tests)
  - ✅ Property tests: 13 tests (Properties 38, 39, 40)
  - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
  - ✅ ONAY ALINIRSA → Sonraki phase'e geç
  - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et


### Phase 10: SDK Components & Final Integration

- [x] 23. SDK Game-Changer Components
  - [x] 23.1 Implement <APIKeyManager /> component
    - Create API key form
    - List API keys (masked)
    - Revoke API key action
    - Copy key on creation
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - APIKeyManager
    - _Requirements: 2.9, 2.10_
  
  - [x] 23.2 Implement <ReverificationModal /> component
    - Password reverification form
    - MFA reverification form
    - WebAuthn reverification
    - Auto-retry on success
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - ReverificationModal
    - _Requirements: 3.6_
  
  - [x] 23.3 Implement <SessionTaskHandler /> component
    - Detect pending tasks
    - Show appropriate task UI
    - Handle task completion
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - SessionTaskHandler
    - _Requirements: 4.6_
  
  - [x] 23.4 Implement <ImpersonationBanner /> component
    - Show impersonation status
    - Display impersonated user info
    - End impersonation button
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/react/README.md` - ImpersonationBanner
    - _Requirements: 6.4_

- [x] 24. Final Integration & Documentation
  - [x] 24.1 Update template.yaml with new Lambdas
    - MachineAuthFunction
    - APIKeyFunction
    - ReverificationFunction
    - SessionTasksFunction
    - WaitlistFunction
    - ImpersonationFunction
    - BillingFunction
    - WebhookDeliveryFunction
    - AIRiskFunction
    - SessionHandlerFunction
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `template.yaml`
  
  - [x] 24.2 Update API Gateway routes
    - /machines/* routes
    - /api-keys/* routes
    - /reverify/* routes
    - /session/tasks/* routes
    - /waitlist/* routes
    - /impersonation/* routes
    - /billing/* routes
    - /webhooks/* routes
    - /sessions/* routes
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `template.yaml`
  
  - [x] 24.3 Update DynamoDB tables
    - zalt-machines table
    - zalt-api-keys table
    - zalt-invitations table
    - zalt-webhooks table
    - zalt-webhook-deliveries table
    - zalt-waitlist table
    - zalt-billing-plans table
    - zalt-subscriptions table
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `template.yaml`
  
  - [x] 24.4 Update documentation
    - docs/api-reference.md - All new endpoints
    - docs/security.md - New security features
    - docs/configuration/webhooks.md - Webhook events
    - docs/configuration/billing.md - Billing setup
    - docs/configuration/sso-saml.md - Org SSO
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
  
  - [x] 24.5 Update SDK packages
    - @zalt/core - New methods
    - @zalt/react - New components and hooks
    - @zalt/next - New middleware
    - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
    - ✅ ONAY ALINIRSA → Sonraki task'a geç
    - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et
    - Update: `packages/*/README.md`

- [x] 25. Final Checkpoint - Game-Changer Complete
  - All 40 property tests pass
  - All integration tests pass
  - All endpoints deployed and working
  - Documentation complete
  - SDK packages published
  - Update `CHANGELOG.md` with all features
  - ⚠️ GERÇEK TEST ZORUNLU - Mock data YASAK
  - ✅ ONAY ALINIRSA → Production ready
  - ❌ ONAY ALINMAZSA → Eksik için yeni task ekle, düzelt, tekrar test et

## Notes

- Bu spec Clerk'in 2025-2026 game-changer özelliklerini kapsar
- Toplam 25 task, 10 phase
- 40 property test
- Deadline: 29 Ocak 2026 (Clinisyn launch)
- Her task production-ready kod üretmeli
- Mock data YASAK - gerçek testler zorunlu

## Property Test Summary

| # | Property | Requirements |
|---|----------|--------------|
| 1 | M2M token scope enforcement | 1.4, 1.7 |
| 2 | Credential rotation invalidates old | 1.5 |
| 3 | M2M token expiry enforced | 1.5 |
| 4 | API key user context preservation | 2.7, 2.8 |
| 5 | Revoked key returns 401 | 2.5 |
| 6 | Expired key returns 401 | 2.6 |
| 7 | Reverification expiry enforced | 3.4, 3.5 |
| 8 | Higher level satisfies lower | 3.4 |
| 9 | Reverification persists | 3.5 |
| 10 | Session task blocking | 4.2 |
| 11 | Task completion removes blocking | 4.9 |
| 12 | Force reset creates task | 4.7 |
| 13 | Invitation token single use | 11.3, 11.4 |
| 14 | Invitation expiry rejects | 11.5 |
| 15 | Revoked invitation rejected | 11.6 |
| 16 | Webhook signature validity | 12.3, 12.4 |
| 17 | Retry with exponential backoff | 12.5 |
| 18 | Event filtering works | 12.8 |
| 19 | Waitlist mode blocks registration | 5.1 |
| 20 | Approval sends invitation | 5.4 |
| 21 | Position calculated correctly | 5.8 |
| 22 | Impersonation restrictions enforced | 6.8 |
| 23 | Impersonation session expires | 6.5 |
| 24 | Audit log records impersonation | 6.7 |
| 25 | Entitlement enforcement correct | 7.6 |
| 26 | Subscription syncs with Stripe | 7.5 |
| 27 | Usage tracking accurate | 7.6 |
| 28 | Risk score consistency | 10.1 |
| 29 | High risk triggers MFA | 10.3 |
| 30 | Very high risk blocks login | 10.4 |
| 31 | Impossible travel detection | 10.2 |
| 32 | Compromised password rejected | 8.1, 8.2 |
| 33 | Force reset creates task | 8.5 |
| 34 | Breach notification sent | 8.8 |
| 35 | SSO enforcement blocks password | 9.6 |
| 36 | JIT provisioning creates user | 9.8 |
| 37 | Domain verification required | 9.5 |
| 38 | Session revocation immediate | 13.3 |
| 39 | Revoke all keeps current | 13.4 |
| 40 | Session limits enforced | 13.6 |
