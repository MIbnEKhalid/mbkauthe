CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE TABLE Ai_history (
    id SERIAL PRIMARY KEY,
    conversation_id UUID NOT NULL DEFAULT uuid_generate_v4(),
    conversation_history JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    temperature FLOAT DEFAULT 1.0,
    username TEXT
);
CREATE INDEX idx_ai_history_username ON Ai_history(username);
CREATE INDEX idx_ai_history_id ON Ai_history(id);




CREATE TABLE user_settings (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    theme VARCHAR(20) DEFAULT 'dark',
    font_size INTEGER DEFAULT 16,
    ai_model VARCHAR(50) DEFAULT 'default',
    temperature FLOAT DEFAULT 1.0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_user_settings_updated_at
BEFORE UPDATE ON user_settings
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();




ALTER TABLE user_settings ADD COLUMN daily_message_limit INTEGER DEFAULT 100;
CREATE TABLE user_message_logs (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    message_count INTEGER DEFAULT 0,
    date DATE DEFAULT CURRENT_DATE,
    CONSTRAINT unique_user_date UNIQUE (username, date)
);