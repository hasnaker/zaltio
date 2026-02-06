# HSD Auth Platform - Disaster Recovery Procedures

## Overview

This document outlines the disaster recovery (DR) procedures for the HSD Auth Platform. The platform is designed to meet the following recovery objectives:

- **Recovery Time Objective (RTO)**: 60 minutes
- **Recovery Point Objective (RPO)**: 15 minutes

## Backup Strategy

### Point-in-Time Recovery (PITR)

All DynamoDB tables have Point-in-Time Recovery enabled, allowing restoration to any point within the last 35 days.

**Tables with PITR:**
- `zalt-users`
- `zalt-realms`
- `zalt-sessions`

### Automated Backups

Daily automated backups are created at 2:00 AM UTC with a 30-day retention period.

**Backup Schedule:**
- Frequency: Daily
- Time: 02:00 UTC
- Retention: 30 days
- Naming Convention: `zalt-backup-{table-name}-{timestamp}`

## Recovery Procedures

### Scenario 1: Single Table Corruption

**Symptoms:**
- Data inconsistencies in a specific table
- Application errors related to specific data

**Recovery Steps:**

1. **Identify the corruption time**
   ```bash
   # Check CloudWatch logs for first error occurrence
   aws logs filter-log-events \
     --log-group-name /aws/lambda/zalt-login \
     --start-time <epoch-ms> \
     --filter-pattern "ERROR"
   ```

2. **Restore table using PITR**
   ```bash
   aws dynamodb restore-table-to-point-in-time \
     --source-table-name zalt-users \
     --target-table-name zalt-users-restored \
     --restore-date-time <timestamp>
   ```

3. **Verify restored data**
   ```bash
   aws dynamodb scan \
     --table-name zalt-users-restored \
     --select COUNT
   ```

4. **Swap tables**
   - Update application configuration to use restored table
   - Or rename tables (requires brief downtime)

5. **Verify application functionality**
   - Run health checks
   - Test authentication flows

### Scenario 2: Complete Database Loss

**Symptoms:**
- All tables inaccessible
- Region-wide DynamoDB outage

**Recovery Steps:**

1. **Assess the situation**
   - Check AWS Service Health Dashboard
   - Determine if regional failover is needed

2. **If regional issue - Failover to secondary region**
   ```bash
   # Update Route 53 health check to fail primary
   aws route53 update-health-check \
     --health-check-id <id> \
     --disabled
   ```

3. **Restore from latest backup**
   ```bash
   # List available backups
   aws dynamodb list-backups \
     --table-name zalt-users
   
   # Restore from backup
   aws dynamodb restore-table-from-backup \
     --target-table-name zalt-users \
     --backup-arn <backup-arn>
   ```

4. **Restore all tables**
   - Repeat for `zalt-realms` and `zalt-sessions`

5. **Update DNS if needed**
   - Point to new region's API Gateway endpoint

6. **Verify full system functionality**

### Scenario 3: Accidental Data Deletion

**Symptoms:**
- Users reporting missing accounts
- Realms or sessions unexpectedly deleted

**Recovery Steps:**

1. **Identify deletion time from audit logs**
   ```bash
   aws logs filter-log-events \
     --log-group-name /aws/lambda/zalt-admin \
     --filter-pattern "REALM_DELETED OR USER_DELETED"
   ```

2. **Use PITR to restore to pre-deletion state**
   ```bash
   aws dynamodb restore-table-to-point-in-time \
     --source-table-name zalt-users \
     --target-table-name zalt-users-recovery \
     --restore-date-time <pre-deletion-timestamp>
   ```

3. **Extract deleted records**
   - Compare restored table with current table
   - Identify missing records

4. **Merge recovered data**
   - Carefully merge deleted records back to production
   - Avoid overwriting newer valid data

### Scenario 4: Security Breach

**Symptoms:**
- Unauthorized access detected
- Suspicious authentication patterns
- Data exfiltration suspected

**Recovery Steps:**

1. **Immediate containment**
   ```bash
   # Rotate JWT secrets immediately
   aws secretsmanager rotate-secret \
     --secret-id zalt/jwt-secrets
   ```

2. **Invalidate all sessions**
   ```bash
   # Clear sessions table (forces re-authentication)
   # Use with caution - affects all users
   ```

3. **Review audit logs**
   - Identify compromised accounts
   - Determine breach timeline

4. **Reset affected credentials**
   - Force password reset for affected users
   - Revoke compromised API keys

5. **Restore from clean backup if needed**
   - Use backup from before breach
   - Re-apply legitimate changes

## Monitoring and Alerting

### CloudWatch Alarms

The following alarms are configured for DR monitoring:

| Alarm | Threshold | Action |
|-------|-----------|--------|
| High Error Rate | >5% for 15 min | Page on-call |
| High Latency | >200ms p95 | Alert team |
| DynamoDB Throttling | >10/min | Scale capacity |
| Backup Failure | Any failure | Alert team |

### Health Checks

- **Endpoint**: `GET /health`
- **Interval**: 30 seconds
- **Unhealthy threshold**: 3 consecutive failures

## Testing DR Procedures

### Quarterly DR Drill

1. **Backup Restoration Test**
   - Restore each table to a test environment
   - Verify data integrity
   - Measure restoration time

2. **Failover Test**
   - Simulate primary region failure
   - Execute failover procedures
   - Measure RTO

3. **Documentation Review**
   - Update procedures based on drill results
   - Train new team members

### Backup Verification

Weekly automated backup verification:
- Restore latest backup to test table
- Run data integrity checks
- Delete test table after verification

## Contact Information

### On-Call Escalation

1. **Primary**: Platform Team Lead
2. **Secondary**: DevOps Engineer
3. **Tertiary**: Engineering Manager

### AWS Support

- Support Plan: Business
- Case Severity: Critical (for production outages)

## Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2024-01-15 | HSD Team | Initial version |
