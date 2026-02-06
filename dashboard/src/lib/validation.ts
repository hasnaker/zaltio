/**
 * Zalt.io Form Validation Utility Library
 * 
 * Provides client-side form validation with comprehensive
 * error messages and validation result types.
 */

// Validation result types
export interface ValidationResult {
  valid: boolean;
  error?: string;
  code?: ValidationErrorCode;
}

export type ValidationErrorCode =
  | 'required'
  | 'invalid_format'
  | 'too_short'
  | 'too_long'
  | 'invalid_email'
  | 'invalid_phone'
  | 'invalid_url'
  | 'password_weak'
  | 'passwords_mismatch'
  | 'invalid_domain';

export interface FieldValidation {
  field: string;
  result: ValidationResult;
}

export interface FormValidationResult {
  valid: boolean;
  errors: FieldValidation[];
}

// Error messages
export const validationMessages: Record<ValidationErrorCode, string> = {
  required: 'This field is required',
  invalid_format: 'Invalid format',
  too_short: 'Value is too short',
  too_long: 'Value is too long',
  invalid_email: 'Please enter a valid email address',
  invalid_phone: 'Please enter a valid phone number',
  invalid_url: 'Please enter a valid URL',
  password_weak: 'Password must be at least 8 characters with uppercase, lowercase, and number',
  passwords_mismatch: 'Passwords do not match',
  invalid_domain: 'Please enter a valid domain name',
};

// Email validation regex (RFC 5322 simplified)
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Phone validation regex (international format)
const PHONE_REGEX = /^\+?[1-9]\d{1,14}$/;

// URL validation regex
const URL_REGEX = /^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_+.~#?&//=]*)$/;

// Domain validation regex
const DOMAIN_REGEX = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

// Password strength regex
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;

/**
 * Validate required field
 */
export function validateRequired(value: unknown): ValidationResult {
  if (value === null || value === undefined) {
    return { valid: false, error: validationMessages.required, code: 'required' };
  }

  if (typeof value === 'string' && value.trim() === '') {
    return { valid: false, error: validationMessages.required, code: 'required' };
  }

  if (Array.isArray(value) && value.length === 0) {
    return { valid: false, error: validationMessages.required, code: 'required' };
  }

  return { valid: true };
}

/**
 * Validate email format
 */
export function validateEmail(email: string): ValidationResult {
  if (!email || email.trim() === '') {
    return { valid: false, error: validationMessages.required, code: 'required' };
  }

  const trimmedEmail = email.trim().toLowerCase();

  if (!EMAIL_REGEX.test(trimmedEmail)) {
    return { valid: false, error: validationMessages.invalid_email, code: 'invalid_email' };
  }

  return { valid: true };
}

/**
 * Validate phone number
 */
export function validatePhone(phone: string): ValidationResult {
  if (!phone || phone.trim() === '') {
    return { valid: false, error: validationMessages.required, code: 'required' };
  }

  // Remove spaces, dashes, and parentheses for validation
  const cleanPhone = phone.replace(/[\s\-()]/g, '');

  if (!PHONE_REGEX.test(cleanPhone)) {
    return { valid: false, error: validationMessages.invalid_phone, code: 'invalid_phone' };
  }

  return { valid: true };
}

/**
 * Validate URL format
 */
export function validateUrl(url: string): ValidationResult {
  if (!url || url.trim() === '') {
    return { valid: false, error: validationMessages.required, code: 'required' };
  }

  if (!URL_REGEX.test(url.trim())) {
    return { valid: false, error: validationMessages.invalid_url, code: 'invalid_url' };
  }

  return { valid: true };
}

/**
 * Validate domain name
 */
export function validateDomain(domain: string): ValidationResult {
  if (!domain || domain.trim() === '') {
    return { valid: false, error: validationMessages.required, code: 'required' };
  }

  if (!DOMAIN_REGEX.test(domain.trim())) {
    return { valid: false, error: validationMessages.invalid_domain, code: 'invalid_domain' };
  }

  return { valid: true };
}

/**
 * Validate string length
 */
export function validateLength(
  value: string,
  options: { min?: number; max?: number }
): ValidationResult {
  const { min, max } = options;

  if (min !== undefined && value.length < min) {
    return {
      valid: false,
      error: `Must be at least ${min} characters`,
      code: 'too_short',
    };
  }

  if (max !== undefined && value.length > max) {
    return {
      valid: false,
      error: `Must be no more than ${max} characters`,
      code: 'too_long',
    };
  }

  return { valid: true };
}

/**
 * Validate password strength
 */
export function validatePassword(password: string): ValidationResult {
  if (!password || password.trim() === '') {
    return { valid: false, error: validationMessages.required, code: 'required' };
  }

  if (!PASSWORD_REGEX.test(password)) {
    return {
      valid: false,
      error: validationMessages.password_weak,
      code: 'password_weak',
    };
  }

  return { valid: true };
}

/**
 * Validate password confirmation
 */
export function validatePasswordMatch(
  password: string,
  confirmPassword: string
): ValidationResult {
  if (password !== confirmPassword) {
    return {
      valid: false,
      error: validationMessages.passwords_mismatch,
      code: 'passwords_mismatch',
    };
  }

  return { valid: true };
}

/**
 * Validate with custom regex
 */
export function validatePattern(
  value: string,
  pattern: RegExp,
  errorMessage?: string
): ValidationResult {
  if (!pattern.test(value)) {
    return {
      valid: false,
      error: errorMessage || validationMessages.invalid_format,
      code: 'invalid_format',
    };
  }

  return { valid: true };
}

/**
 * Combine multiple validations
 */
export function combineValidations(
  ...validations: ValidationResult[]
): ValidationResult {
  for (const validation of validations) {
    if (!validation.valid) {
      return validation;
    }
  }
  return { valid: true };
}

/**
 * Validate a form with multiple fields
 */
export function validateForm(
  fields: Array<{ field: string; value: unknown; validators: Array<(value: unknown) => ValidationResult> }>
): FormValidationResult {
  const errors: FieldValidation[] = [];

  for (const { field, value, validators } of fields) {
    for (const validator of validators) {
      const result = validator(value);
      if (!result.valid) {
        errors.push({ field, result });
        break; // Stop at first error for this field
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Contact form validation
 */
export interface ContactFormData {
  name: string;
  email: string;
  company?: string;
  message: string;
}

export function validateContactForm(data: ContactFormData): FormValidationResult {
  const errors: FieldValidation[] = [];

  // Validate name
  const nameRequired = validateRequired(data.name);
  if (!nameRequired.valid) {
    errors.push({ field: 'name', result: nameRequired });
  } else {
    const nameLength = validateLength(data.name, { min: 2, max: 100 });
    if (!nameLength.valid) {
      errors.push({ field: 'name', result: nameLength });
    }
  }

  // Validate email
  const emailResult = validateEmail(data.email);
  if (!emailResult.valid) {
    errors.push({ field: 'email', result: emailResult });
  }

  // Validate company (optional but if provided, validate length)
  if (data.company && data.company.trim() !== '') {
    const companyLength = validateLength(data.company, { max: 200 });
    if (!companyLength.valid) {
      errors.push({ field: 'company', result: companyLength });
    }
  }

  // Validate message
  const messageRequired = validateRequired(data.message);
  if (!messageRequired.valid) {
    errors.push({ field: 'message', result: messageRequired });
  } else {
    const messageLength = validateLength(data.message, { min: 10, max: 5000 });
    if (!messageLength.valid) {
      errors.push({ field: 'message', result: messageLength });
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Newsletter subscription validation
 */
export function validateNewsletterEmail(email: string): ValidationResult {
  return validateEmail(email);
}

/**
 * Lead form validation
 */
export interface LeadFormData {
  name: string;
  email: string;
  company: string;
  phone?: string;
  message?: string;
}

export function validateLeadForm(data: LeadFormData): FormValidationResult {
  const errors: FieldValidation[] = [];

  // Validate name
  const nameRequired = validateRequired(data.name);
  if (!nameRequired.valid) {
    errors.push({ field: 'name', result: nameRequired });
  }

  // Validate email
  const emailResult = validateEmail(data.email);
  if (!emailResult.valid) {
    errors.push({ field: 'email', result: emailResult });
  }

  // Validate company
  const companyRequired = validateRequired(data.company);
  if (!companyRequired.valid) {
    errors.push({ field: 'company', result: companyRequired });
  }

  // Validate phone (optional)
  if (data.phone && data.phone.trim() !== '') {
    const phoneResult = validatePhone(data.phone);
    if (!phoneResult.valid) {
      errors.push({ field: 'phone', result: phoneResult });
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Get error message for a field from validation result
 */
export function getFieldError(
  result: FormValidationResult,
  fieldName: string
): string | undefined {
  const fieldError = result.errors.find((e) => e.field === fieldName);
  return fieldError?.result.error;
}

/**
 * Check if a field has an error
 */
export function hasFieldError(
  result: FormValidationResult,
  fieldName: string
): boolean {
  return result.errors.some((e) => e.field === fieldName);
}

// Export all functions
export const validation = {
  validateRequired,
  validateEmail,
  validatePhone,
  validateUrl,
  validateDomain,
  validateLength,
  validatePassword,
  validatePasswordMatch,
  validatePattern,
  combineValidations,
  validateForm,
  validateContactForm,
  validateNewsletterEmail,
  validateLeadForm,
  getFieldError,
  hasFieldError,
  validationMessages,
};

export default validation;
