/**
 * SMS Service - AWS SNS Integration
 * Validates: Requirements 2.2 (MFA - SMS with risk acceptance)
 * 
 * ⚠️ SECURITY WARNING:
 * SMS MFA is vulnerable to:
 * - SS7 protocol attacks
 * - SIM swapping attacks
 * - Social engineering
 * 
 * SMS should only be used when:
 * 1. User explicitly accepts the risk
 * 2. More secure methods (TOTP, WebAuthn) are not available
 * 3. Realm policy allows SMS MFA
 * 
 * @healthcare NOT recommended for HIPAA-sensitive operations
 */

import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import crypto from 'crypto';

// SNS Client (lazy init)
let snsClient: SNSClient | null = null;
function getSNSClient(): SNSClient {
  if (!snsClient) {
    snsClient = new SNSClient({
      region: process.env.AWS_REGION || 'eu-central-1'
    });
  }
  return snsClient;
}

/**
 * SMS Configuration
 */
export const SMS_CONFIG = {
  codeLength: 6,
  codeExpirySeconds: 300, // 5 minutes (shorter than email for security)
  maxAttempts: 3,
  rateLimitPerHour: 3, // Stricter than email due to cost and security
  senderID: process.env.SMS_SENDER_ID || 'Zalt', // Max 11 chars
};

/**
 * SMS Send Result
 */
export interface SMSSendResult {
  success: boolean;
  messageId?: string;
  error?: string;
}

/**
 * SMS Verification Data
 */
export interface SMSVerificationData {
  code: string;
  codeHash: string;
  expiresAt: number;
  attempts: number;
  phoneNumber: string;
  riskAccepted: boolean;
}

/**
 * SMS Risk Warning - Must be shown to user before enabling SMS MFA
 */
export const SMS_RISK_WARNING = {
  title: 'SMS Güvenlik Uyarısı',
  message: 'SMS doğrulama aşağıdaki saldırılara karşı savunmasızdır:',
  risks: [
    'SIM Swap saldırıları - Saldırgan telefon numaranızı ele geçirebilir',
    'SS7 protokol açıkları - SMS mesajları intercept edilebilir',
    'Sosyal mühendislik - Operatör çalışanları kandırılabilir'
  ],
  recommendation: 'Daha güvenli bir deneyim için Authenticator uygulaması veya Passkey kullanmanızı öneriyoruz.',
  acceptanceRequired: true
};

/**
 * Generate 6-digit SMS verification code
 */
export function generateSMSCode(): string {
  const buffer = crypto.randomBytes(4);
  const num = buffer.readUInt32BE(0);
  return (num % 900000 + 100000).toString();
}

/**
 * Hash SMS code for secure storage
 */
export function hashSMSCode(code: string): string {
  return crypto.createHash('sha256').update(code).digest('hex');
}

/**
 * Verify SMS code against hash
 */
export function verifySMSCode(code: string, hash: string): boolean {
  const codeHash = hashSMSCode(code);
  return crypto.timingSafeEqual(
    Buffer.from(codeHash, 'hex'),
    Buffer.from(hash, 'hex')
  );
}

/**
 * Create SMS verification data
 */
export function createSMSVerificationData(phoneNumber: string, riskAccepted: boolean): SMSVerificationData {
  const code = generateSMSCode();
  return {
    code,
    codeHash: hashSMSCode(code),
    expiresAt: Date.now() + (SMS_CONFIG.codeExpirySeconds * 1000),
    attempts: 0,
    phoneNumber,
    riskAccepted
  };
}

/**
 * Normalize phone number to E.164 format
 * Examples: +905551234567, +14155551234
 */
export function normalizePhoneNumber(phone: string): string {
  // Remove all non-digit characters except leading +
  let normalized = phone.replace(/[^\d+]/g, '');
  
  // Ensure it starts with +
  if (!normalized.startsWith('+')) {
    // Assume Turkish number if no country code
    if (normalized.startsWith('0')) {
      normalized = '+9' + normalized; // 0532... -> +90532...
    } else if (normalized.length === 10) {
      normalized = '+90' + normalized; // 5321234567 -> +905321234567
    } else {
      normalized = '+' + normalized;
    }
  }
  
  return normalized;
}

/**
 * Validate phone number format
 */
export function validatePhoneNumber(phone: string): { valid: boolean; error?: string } {
  const normalized = normalizePhoneNumber(phone);
  
  // E.164 format: + followed by 10-15 digits
  const e164Regex = /^\+[1-9]\d{9,14}$/;
  
  if (!e164Regex.test(normalized)) {
    return {
      valid: false,
      error: 'Geçersiz telefon numarası formatı. Örnek: +905551234567'
    };
  }
  
  return { valid: true };
}

/**
 * Send SMS via AWS SNS
 */
export async function sendSMS(
  phoneNumber: string,
  message: string
): Promise<SMSSendResult> {
  try {
    const normalized = normalizePhoneNumber(phoneNumber);
    
    // Validate phone number
    const validation = validatePhoneNumber(normalized);
    if (!validation.valid) {
      return {
        success: false,
        error: validation.error
      };
    }

    const command = new PublishCommand({
      PhoneNumber: normalized,
      Message: message,
      MessageAttributes: {
        'AWS.SNS.SMS.SenderID': {
          DataType: 'String',
          StringValue: SMS_CONFIG.senderID
        },
        'AWS.SNS.SMS.SMSType': {
          DataType: 'String',
          StringValue: 'Transactional' // Higher delivery priority
        }
      }
    });

    const result = await getSNSClient().send(command);

    return {
      success: true,
      messageId: result.MessageId
    };
  } catch (error) {
    console.error('SMS send error:', error);
    return {
      success: false,
      error: (error as Error).message
    };
  }
}

/**
 * Send SMS verification code
 */
export async function sendSMSVerificationCode(
  phoneNumber: string,
  code: string,
  realmName: string
): Promise<SMSSendResult> {
  const message = `${realmName} doğrulama kodunuz: ${code}\n\nBu kod 5 dakika içinde geçerliliğini yitirecektir.\n\nBu kodu kimseyle paylaşmayın.`;
  
  return sendSMS(phoneNumber, message);
}

/**
 * Send SMS login alert
 */
export async function sendSMSLoginAlert(
  phoneNumber: string,
  realmName: string,
  location?: string,
  device?: string
): Promise<SMSSendResult> {
  let message = `${realmName}: Hesabınıza yeni bir giriş yapıldı.`;
  
  if (location) {
    message += `\nKonum: ${location}`;
  }
  if (device) {
    message += `\nCihaz: ${device}`;
  }
  
  message += '\n\nBu siz değilseniz, hemen şifrenizi değiştirin.';
  
  return sendSMS(phoneNumber, message);
}

/**
 * Check if SMS MFA is allowed for realm
 */
export function isSMSAllowedForRealm(realmSettings?: {
  mfa_config?: {
    allowed_methods?: string[];
    sms_risk_accepted?: boolean;
  };
}): boolean {
  if (!realmSettings?.mfa_config) {
    return false; // Default: SMS not allowed
  }
  
  const { allowed_methods, sms_risk_accepted } = realmSettings.mfa_config;
  
  // SMS must be explicitly allowed AND risk must be accepted at realm level
  return (
    Array.isArray(allowed_methods) &&
    allowed_methods.includes('sms') &&
    sms_risk_accepted === true
  );
}

/**
 * Get SMS MFA setup requirements
 */
export function getSMSSetupRequirements(): {
  riskWarning: typeof SMS_RISK_WARNING;
  requirements: string[];
} {
  return {
    riskWarning: SMS_RISK_WARNING,
    requirements: [
      'Geçerli bir telefon numarası (E.164 formatında)',
      'SMS risk uyarısının kabul edilmesi',
      'Realm politikasının SMS MFA\'ya izin vermesi'
    ]
  };
}
