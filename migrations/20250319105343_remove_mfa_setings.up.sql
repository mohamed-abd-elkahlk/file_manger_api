-- Remove existing mfa_settings column if it exists
ALTER TABLE users DROP COLUMN IF EXISTS mfa_settings;

-- Add new mfa_settings column with TEXT type to store MfaType
ALTER TABLE users
ADD COLUMN mfa_settings TEXT CHECK (mfa_settings IN ('Totp', 'Email',Null)) DEFAULT Null;
