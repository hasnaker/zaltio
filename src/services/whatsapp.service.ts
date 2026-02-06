/**
 * WhatsApp Business API Service
 * Meta Cloud API ile OTP gönderimi
 * 
 * Avantajlar:
 * - ✅ Logo ve şirket adı görünür
 * - ✅ Mavi tik (doğrulanmış işletme)
 * - ✅ "Kodu Kopyala" butonu
 * - ✅ E2E şifreli (SMS'ten güvenli)
 * - ✅ %99+ delivery rate
 * - ✅ SMS'ten ucuz (~$0.035/mesaj)
 * 
 * @see https://developers.facebook.com/docs/whatsapp/cloud-api/
 */

import crypto from 'crypto';

/**
 * WhatsApp Configuration
 */
export interface WhatsAppConfig {
  phoneNumberId: string;    // WhatsApp Business Phone Number ID
  accessToken: string;      // Meta Business Access Token
  apiVersion?: string;      // API version (default: v18.0)
}

/**
 * WhatsApp OTP Template Configuration
 */
export interface OTPTemplateConfig {
  templateName: string;     // Pre-approved template name
  language: string;         // Template language code (e.g., 'tr')
}

/**
 * WhatsApp Send Result
 */
export interface WhatsAppSendResult {
  success: boolean;
  messageId?: string;
  error?: string;
  errorCode?: string;
}

/**
 * WhatsApp OTP Verification Data
 */
export interface WhatsAppOTPData {
  code: string;
  codeHash: string;
  expiresAt: number;
  attempts: number;
  phoneNumber: string;
  messageId?: string;
}

/**
 * WhatsApp Service Configuration
 */
export const WHATSAPP_CONFIG = {
  codeLength: 6,
  codeExpirySeconds: 300,   // 5 minutes
  maxAttempts: 3,
  rateLimitPerHour: 5,      // More generous than SMS (cheaper)
  apiBaseUrl: 'https://graph.facebook.com',
  apiVersion: 'v18.0',
};

/**
 * Default OTP Template (must be pre-approved by Meta)
 * Template name format: authentication_otp_<language>
 */
export const DEFAULT_OTP_TEMPLATE: OTPTemplateConfig = {
  templateName: 'authentication_otp',
  language: 'tr',
};

/**
 * Generate 6-digit OTP code
 */
export function generateOTPCode(): string {
  const buffer = crypto.randomBytes(4);
  const num = buffer.readUInt32BE(0);
  return (num % 900000 + 100000).toString();
}

/**
 * Hash OTP code for secure storage
 */
export function hashOTPCode(code: string): string {
  return crypto.createHash('sha256').update(code).digest('hex');
}

/**
 * Verify OTP code against hash (constant-time)
 */
export function verifyOTPCode(code: string, hash: string): boolean {
  const codeHash = hashOTPCode(code);
  return crypto.timingSafeEqual(
    Buffer.from(codeHash, 'hex'),
    Buffer.from(hash, 'hex')
  );
}

/**
 * Create WhatsApp OTP verification data
 */
export function createWhatsAppOTPData(phoneNumber: string): WhatsAppOTPData {
  const code = generateOTPCode();
  return {
    code,
    codeHash: hashOTPCode(code),
    expiresAt: Date.now() + (WHATSAPP_CONFIG.codeExpirySeconds * 1000),
    attempts: 0,
    phoneNumber: normalizePhoneNumber(phoneNumber),
  };
}

/**
 * Normalize phone number to E.164 format (without +)
 * WhatsApp API requires number without + prefix
 */
export function normalizePhoneNumber(phone: string): string {
  // Remove all non-digit characters
  let normalized = phone.replace(/\D/g, '');
  
  // Handle Turkish numbers
  if (normalized.startsWith('0') && normalized.length === 11) {
    // 05321234567 -> 905321234567
    normalized = '9' + normalized;
  } else if (normalized.length === 10 && normalized.startsWith('5')) {
    // 5321234567 -> 905321234567
    normalized = '90' + normalized;
  }
  
  return normalized;
}

/**
 * Validate phone number for WhatsApp
 */
export function validateWhatsAppNumber(phone: string): { valid: boolean; error?: string } {
  const normalized = normalizePhoneNumber(phone);
  
  // Must be 10-15 digits
  if (!/^\d{10,15}$/.test(normalized)) {
    return {
      valid: false,
      error: 'Geçersiz telefon numarası formatı. Örnek: 5321234567'
    };
  }
  
  return { valid: true };
}

/**
 * WhatsApp Business API Client
 */
export class WhatsAppClient {
  private phoneNumberId: string;
  private accessToken: string;
  private apiVersion: string;
  private baseUrl: string;

  constructor(config: WhatsAppConfig) {
    this.phoneNumberId = config.phoneNumberId;
    this.accessToken = config.accessToken;
    this.apiVersion = config.apiVersion || WHATSAPP_CONFIG.apiVersion;
    this.baseUrl = `${WHATSAPP_CONFIG.apiBaseUrl}/${this.apiVersion}`;
  }

  /**
   * Send OTP via WhatsApp Authentication Template
   * Uses Meta's pre-approved authentication template format
   */
  async sendOTP(
    phoneNumber: string,
    code: string,
    templateConfig: OTPTemplateConfig = DEFAULT_OTP_TEMPLATE
  ): Promise<WhatsAppSendResult> {
    const normalized = normalizePhoneNumber(phoneNumber);
    
    // Validate phone number
    const validation = validateWhatsAppNumber(normalized);
    if (!validation.valid) {
      return { success: false, error: validation.error };
    }

    const url = `${this.baseUrl}/${this.phoneNumberId}/messages`;
    
    // Authentication template message format
    // @see https://developers.facebook.com/docs/whatsapp/cloud-api/guides/send-message-templates/auth-otp-template-messages/
    const payload = {
      messaging_product: 'whatsapp',
      recipient_type: 'individual',
      to: normalized,
      type: 'template',
      template: {
        name: templateConfig.templateName,
        language: {
          code: templateConfig.language,
        },
        components: [
          {
            type: 'body',
            parameters: [
              {
                type: 'text',
                text: code,
              },
            ],
          },
          {
            type: 'button',
            sub_type: 'url',
            index: '0',
            parameters: [
              {
                type: 'text',
                text: code,
              },
            ],
          },
        ],
      },
    };

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (!response.ok) {
        console.error('WhatsApp API error:', data);
        return {
          success: false,
          error: data.error?.message || 'WhatsApp mesajı gönderilemedi',
          errorCode: data.error?.code?.toString(),
        };
      }

      return {
        success: true,
        messageId: data.messages?.[0]?.id,
      };
    } catch (error) {
      console.error('WhatsApp send error:', error);
      return {
        success: false,
        error: (error as Error).message,
      };
    }
  }

  /**
   * Send OTP with Copy Code button (simpler template)
   * This uses the copy_code button type for easier user experience
   */
  async sendOTPWithCopyButton(
    phoneNumber: string,
    code: string,
    templateName: string = 'authentication_copy_code'
  ): Promise<WhatsAppSendResult> {
    const normalized = normalizePhoneNumber(phoneNumber);
    
    const validation = validateWhatsAppNumber(normalized);
    if (!validation.valid) {
      return { success: false, error: validation.error };
    }

    const url = `${this.baseUrl}/${this.phoneNumberId}/messages`;
    
    // Copy code button template
    const payload = {
      messaging_product: 'whatsapp',
      recipient_type: 'individual',
      to: normalized,
      type: 'template',
      template: {
        name: templateName,
        language: {
          code: 'tr',
        },
        components: [
          {
            type: 'body',
            parameters: [
              {
                type: 'text',
                text: code,
              },
            ],
          },
          {
            type: 'button',
            sub_type: 'copy_code',
            index: '0',
            parameters: [
              {
                type: 'coupon_code',
                coupon_code: code,
              },
            ],
          },
        ],
      },
    };

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (!response.ok) {
        console.error('WhatsApp API error:', data);
        return {
          success: false,
          error: data.error?.message || 'WhatsApp mesajı gönderilemedi',
          errorCode: data.error?.code?.toString(),
        };
      }

      return {
        success: true,
        messageId: data.messages?.[0]?.id,
      };
    } catch (error) {
      console.error('WhatsApp send error:', error);
      return {
        success: false,
        error: (error as Error).message,
      };
    }
  }

  /**
   * Check if WhatsApp number is registered
   * Useful for fallback to SMS if user doesn't have WhatsApp
   */
  async checkNumberStatus(phoneNumber: string): Promise<{
    registered: boolean;
    error?: string;
  }> {
    const normalized = normalizePhoneNumber(phoneNumber);
    const url = `${this.baseUrl}/${this.phoneNumberId}/contacts`;

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${this.accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          blocking: 'wait',
          contacts: [`+${normalized}`],
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        return { registered: false, error: data.error?.message };
      }

      const contact = data.contacts?.[0];
      return {
        registered: contact?.status === 'valid',
      };
    } catch (error) {
      return {
        registered: false,
        error: (error as Error).message,
      };
    }
  }
}

/**
 * Get WhatsApp client from environment/secrets
 */
let whatsappClient: WhatsAppClient | null = null;

export async function getWhatsAppClient(): Promise<WhatsAppClient> {
  if (whatsappClient) {
    return whatsappClient;
  }

  // Get credentials from environment or Secrets Manager
  const phoneNumberId = process.env.WHATSAPP_PHONE_NUMBER_ID;
  const accessToken = process.env.WHATSAPP_ACCESS_TOKEN;

  if (!phoneNumberId || !accessToken) {
    throw new Error('WhatsApp credentials not configured');
  }

  whatsappClient = new WhatsAppClient({
    phoneNumberId,
    accessToken,
  });

  return whatsappClient;
}

/**
 * Send WhatsApp OTP (convenience function)
 */
export async function sendWhatsAppOTP(
  phoneNumber: string,
  code: string
): Promise<WhatsAppSendResult> {
  const client = await getWhatsAppClient();
  return client.sendOTPWithCopyButton(phoneNumber, code);
}
