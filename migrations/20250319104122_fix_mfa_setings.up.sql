-- Add MFA settings column with JSONB type (nullable)
ALTER TABLE users ALTER COLUMN mfa_settings SET DEFAULT NULL;
