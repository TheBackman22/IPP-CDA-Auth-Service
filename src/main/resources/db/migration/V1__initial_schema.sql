-- Create schema
CREATE SCHEMA IF NOT EXISTS auth_schema;

-- Users table
CREATE TABLE auth_schema.users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           VARCHAR(255) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,
    display_name    VARCHAR(100),
    timezone        VARCHAR(50) NOT NULL DEFAULT 'UTC',
    email_verified  BOOLEAN NOT NULL DEFAULT FALSE,
    active          BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Refresh tokens table (for blacklisting/tracking)
CREATE TABLE auth_schema.refresh_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES auth_schema.users(id) ON DELETE CASCADE,
    token_hash      VARCHAR(255) NOT NULL UNIQUE,
    expires_at      TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_refresh_token_user
        FOREIGN KEY (user_id) REFERENCES auth_schema.users(id)
);

-- Indexes
CREATE INDEX idx_users_email ON auth_schema.users(email);
CREATE INDEX idx_users_active ON auth_schema.users(active) WHERE active = true;
CREATE INDEX idx_refresh_tokens_user_id ON auth_schema.refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_hash ON auth_schema.refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_expires ON auth_schema.refresh_tokens(expires_at)
    WHERE revoked = false;

-- Updated_at trigger
CREATE OR REPLACE FUNCTION auth_schema.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON auth_schema.users
    FOR EACH ROW EXECUTE FUNCTION auth_schema.update_updated_at_column();
