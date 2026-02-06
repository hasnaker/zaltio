/**
 * Tediyat Invitation Email Service
 * Turkish email templates for invitations
 * 
 * Validates: Requirements 12.1
 */

export interface InvitationEmailData {
  inviteeName: string;
  inviterName: string;
  tenantName: string;
  roleName: string;
  inviteUrl: string;
  expiresAt: string;
}

/**
 * Generate invitation email subject
 */
export function getInvitationEmailSubject(tenantName: string): string {
  return `${tenantName} şirketine davet edildiniz - Tediyat`;
}

/**
 * Generate invitation email HTML body
 */
export function getInvitationEmailHtml(data: InvitationEmailData): string {
  const expiryDate = new Date(data.expiresAt).toLocaleDateString('tr-TR', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });

  return `
<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Tediyat Davet</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
  <div style="background: linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%); padding: 30px; border-radius: 12px 12px 0 0; text-align: center;">
    <h1 style="color: white; margin: 0; font-size: 24px;">Tediyat</h1>
    <p style="color: rgba(255,255,255,0.9); margin: 10px 0 0 0;">Ön Muhasebe Platformu</p>
  </div>
  
  <div style="background: #f8fafc; padding: 30px; border: 1px solid #e2e8f0; border-top: none;">
    <h2 style="color: #1e293b; margin-top: 0;">Merhaba${data.inviteeName ? ` ${data.inviteeName}` : ''},</h2>
    
    <p style="color: #475569;">
      <strong>${data.inviterName}</strong> sizi <strong>${data.tenantName}</strong> şirketine 
      <strong>${data.roleName}</strong> olarak davet etti.
    </p>
    
    <p style="color: #475569;">
      Daveti kabul etmek ve Tediyat'a katılmak için aşağıdaki butona tıklayın:
    </p>
    
    <div style="text-align: center; margin: 30px 0;">
      <a href="${data.inviteUrl}" 
         style="display: inline-block; background: #2563eb; color: white; padding: 14px 32px; 
                text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 16px;">
        Daveti Kabul Et
      </a>
    </div>
    
    <p style="color: #64748b; font-size: 14px;">
      Bu davet <strong>${expiryDate}</strong> tarihine kadar geçerlidir.
    </p>
    
    <hr style="border: none; border-top: 1px solid #e2e8f0; margin: 30px 0;">
    
    <p style="color: #64748b; font-size: 13px;">
      Eğer bu daveti beklemiyorsanız, bu e-postayı görmezden gelebilirsiniz.
    </p>
    
    <p style="color: #94a3b8; font-size: 12px; margin-bottom: 0;">
      Buton çalışmıyorsa, bu linki tarayıcınıza kopyalayın:<br>
      <a href="${data.inviteUrl}" style="color: #2563eb; word-break: break-all;">${data.inviteUrl}</a>
    </p>
  </div>
  
  <div style="background: #1e293b; padding: 20px; border-radius: 0 0 12px 12px; text-align: center;">
    <p style="color: #94a3b8; margin: 0; font-size: 13px;">
      © 2026 Tediyat. Tüm hakları saklıdır.
    </p>
  </div>
</body>
</html>
  `.trim();
}

/**
 * Generate invitation email plain text body
 */
export function getInvitationEmailText(data: InvitationEmailData): string {
  const expiryDate = new Date(data.expiresAt).toLocaleDateString('tr-TR', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });

  return `
Merhaba${data.inviteeName ? ` ${data.inviteeName}` : ''},

${data.inviterName} sizi ${data.tenantName} şirketine ${data.roleName} olarak davet etti.

Daveti kabul etmek için aşağıdaki linke tıklayın:
${data.inviteUrl}

Bu davet ${expiryDate} tarihine kadar geçerlidir.

Eğer bu daveti beklemiyorsanız, bu e-postayı görmezden gelebilirsiniz.

---
Tediyat - Ön Muhasebe Platformu
  `.trim();
}
