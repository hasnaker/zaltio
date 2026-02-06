# Requirements Document

## Introduction

Zalt.io Auth Platform Lambda fonksiyonlarının AWS'e düzgün deploy edilmesi için gerekli düzeltmeler. Mevcut sorun: SAM build sonrası handler path'leri Lambda runtime tarafından doğru parse edilemiyor. AWS Kiro wrapper dosyası çözümü uyguladı ama kalıcı ve profesyonel bir çözüm gerekiyor.

## Glossary

- **SAM**: AWS Serverless Application Model - Lambda deployment aracı
- **Handler**: Lambda fonksiyonunun entry point'i (dosya.export formatında)
- **esbuild**: Hızlı JavaScript/TypeScript bundler
- **Wrapper**: Handler'ı re-export eden ara dosya

## Requirements

### Requirement 1: esbuild ile Lambda Bundling

**User Story:** As a developer, I want Lambda functions to be bundled with esbuild, so that handler paths work correctly without wrapper files.

#### Acceptance Criteria

1. WHEN SAM build runs, THE Build_System SHALL use esbuild to bundle each Lambda function
2. WHEN bundling completes, THE Build_System SHALL produce a single index.js file per Lambda
3. THE Handler_Path SHALL be `index.handler` for all Lambda functions (except health which has multiple exports)
4. WHEN deploying, THE Lambda_Runtime SHALL correctly resolve the handler without errors

### Requirement 2: Handler Export Standardization

**User Story:** As a developer, I want all handlers to export a consistent `handler` function, so that deployment is predictable.

#### Acceptance Criteria

1. THE Login_Handler SHALL export `handler` function
2. THE Register_Handler SHALL export `handler` function
3. THE Refresh_Handler SHALL export `handler` function
4. THE Logout_Handler SHALL export `handler` function
5. THE SSO_Handler SHALL export `handler` function
6. THE Admin_Handler SHALL export `handler` function with internal routing
7. THE Health_Handler SHALL export `healthHandler`, `livenessHandler`, `readinessHandler` functions

### Requirement 3: template.yaml Handler Path Correction

**User Story:** As a developer, I want template.yaml to have correct handler paths, so that SAM deploy works without manual intervention.

#### Acceptance Criteria

1. WHEN template.yaml is updated, THE Handler_Paths SHALL match the bundled output structure
2. THE HealthFunction Handler SHALL be `dist/handlers/health.handler.healthHandler`
3. THE LoginFunction Handler SHALL be `dist/handlers/login.handler.handler`
4. THE RegisterFunction Handler SHALL be `dist/handlers/register.handler.handler`
5. THE RefreshFunction Handler SHALL be `dist/handlers/refresh.handler.handler`
6. THE LogoutFunction Handler SHALL be `dist/handlers/logout.handler.handler`
7. THE SSOFunction Handler SHALL be `dist/handlers/sso.handler.handler`
8. THE AdminFunction Handler SHALL be `dist/handlers/admin.handler.handler`

### Requirement 4: Admin Handler Router

**User Story:** As a developer, I want admin handler to have a single entry point with internal routing, so that one Lambda can handle multiple admin endpoints.

#### Acceptance Criteria

1. WHEN a request comes to /admin/*, THE Admin_Handler SHALL route based on HTTP method and path
2. THE Admin_Handler SHALL export a single `handler` function
3. WHEN routing, THE Admin_Handler SHALL call the appropriate internal handler (listRealmsHandler, createRealmHandler, etc.)

### Requirement 5: Health Check Table Configuration

**User Story:** As a developer, I want health check to only verify core tables, so that it doesn't fail on optional tables.

#### Acceptance Criteria

1. THE Health_Service SHALL only check core tables: zalt-users, zalt-realms, zalt-sessions
2. THE AWS_Config SHALL separate core tables from extended tables
3. WHEN extended tables don't exist, THE Health_Check SHALL still return healthy status
