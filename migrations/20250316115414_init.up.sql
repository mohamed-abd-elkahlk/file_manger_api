-- Add up migration script here


CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT CHECK (role IN ('Admin', 'User', 'Guest')) DEFAULT 'User',
    extra_data JSONB
);
