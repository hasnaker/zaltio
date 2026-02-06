# Implementation Plan: Lambda Deployment Fix

## Overview

Zalt.io Lambda fonksiyonlarının AWS'e düzgün deploy edilmesi için handler path düzeltmeleri ve admin router implementasyonu.

## Tasks

- [x] 1.  Fix template.yaml handler paths
  - Update all Lambda handler paths to correct format
  - LoginFunction: `dist/handlers/login.handler.handler` ✅
  - RegisterFunction: `dist/handlers/register.handler.handler` ✅
  - RefreshFunction: `dist/handlers/refresh.handler.handler` ✅
  - LogoutFunction: `dist/handlers/logout.handler.handler` ✅
  - SSOFunction: `dist/handlers/sso.handler.handler` ✅
  - AdminFunction: `dist/handlers/admin.handler.handler` ✅
  - HealthFunction: `dist/handlers/health.handler.healthHandler` ✅
  - _Requirements: 3.2-3.8_

- [x] 2. Add admin handler router
  - [x] 2.1 Create router function in admin.handler.ts
    - Add `handler` export that routes based on path/method ✅
    - Route to existing handler functions ✅
    - _Requirements: 4.1, 4.2, 4.3_
  - [x] 2.2 Add all admin routes to template.yaml
    - Add user management routes (GET/DELETE /admin/users, POST suspend/activate/unlock)
    - Add session management routes (GET/DELETE /admin/sessions)
    - Add MFA reset route (POST /admin/users/{id}/mfa/reset)
    - _Requirements: 4.1_

- [x] 3. Fix remaining handler paths in template.yaml
  - Update RefreshFunction Handler to `dist/handlers/refresh.handler.handler`
  - Update LogoutFunction Handler to `dist/handlers/logout.handler.handler`
  - Update SSOFunction Handler to `dist/handlers/sso.handler.handler`
  - Update AdminFunction Handler to `dist/handlers/admin.handler.handler`
  - _Requirements: 3.4, 3.5, 3.7, 3.8_

- [x] 4. Update AWS config for table separation
  - Core vs extended tables separation ✅
  - Verify health check only validates core tables ✅
  - _Requirements: 5.1, 5.2_

- [x] 5. Checkpoint - Verify handler exports
  - Ensure all handlers export correct functions
  - Run `npm run build` to verify compilation
  - _Requirements: 2.1-2.7_

- [x] 6. Final checkpoint
  - Run `sam build`
  - Verify dist/ structure
  - Ready for AWS Kiro to deploy

## Notes

- Health handler path is already correct: `dist/handlers/health.handler.healthHandler`
- AWS Kiro will handle actual deployment after these changes
- No wrapper files needed with correct handler paths
- Admin router is fully implemented with all routes (realms, users, sessions, MFA reset)
- Handler exports are standardized across all Lambda functions

