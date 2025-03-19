-- Add up migration script here
BEGIN;

-- Drop the existing users table if it exists
DROP TABLE IF EXISTS users;

-- Ensure the uuid-ossp extension is available for UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create the new users table with all required columns
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username TEXT NOT NULL,
    is_verified BOOLEAN NOT NULL DEFAULT FALSE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('Admin', 'User', 'Guest')),
    data JSONB,

    -- Multi-Factor Authentication (MFA)
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_type TEXT CHECK (mfa_type IN ('Totp', 'Email', NULL)) DEFAULT NULL, -- Replaces mfa_settings
    totp_secret TEXT, -- TOTP Secret (Google Authenticator)
    email_otp TEXT, -- Last generated Email OTP
    backup_codes TEXT[], -- Backup codes for MFA recovery
    mfa_recovery_codes_used TEXT[], -- Used backup codes

    -- Password reset fields
    password_reset_token TEXT,
    password_reset_expiry TIMESTAMP WITH TIME ZONE,

    -- Email verification fields
    email_verification_token TEXT,
    email_verification_expiry TIMESTAMP WITH TIME ZONE,

    -- Session management fields
    last_login_at TIMESTAMP WITH TIME ZONE,
    failed_login_attempts INT NOT NULL DEFAULT 0,
    account_locked_until TIMESTAMP WITH TIME ZONE,

    -- Refresh token fields
    refresh_token TEXT,
    refresh_token_expiry TIMESTAMP WITH TIME ZONE,

    -- Security fields
    last_password_change TIMESTAMP WITH TIME ZONE,
    password_history TEXT[], -- List of previously used password hashes

    -- Account locking functionality
    locked BOOLEAN NOT NULL DEFAULT FALSE,

    locked_until TIMESTAMP WITH TIME ZONE
);

COMMIT;