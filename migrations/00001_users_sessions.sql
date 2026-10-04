-- +goose Up
CREATE TABLE users (
    id uuid PRIMARY KEY,
    login text NOT NULL UNIQUE CHECK (login ~ '^[a-z0-9_]{3,32}$'),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
    role text NOT NULL CHECK (role IN ('student', 'tutor')),
    password_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sessions_user_id_idx ON sessions(user_id);
CREATE INDEX sessions_expires_at_idx ON sessions(expires_at);

-- +goose Down
DROP TABLE sessions;
DROP TABLE users;
