// Package store implements the PostgreSQL persistence boundary for users and sessions.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrLoginTaken = errors.New("login is already registered")
	ErrNotFound   = errors.New("not found")
)

type User struct {
	ID    string `json:"id"`
	Login string `json:"login"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

type Store struct{ pool *pgxpool.Pool }

func Open(ctx context.Context, databaseURL string) (*Store, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	config.MaxConns = 8
	config.ConnConfig.ConnectTimeout = 5 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) Ready(ctx context.Context) error {
	var ready bool
	err := s.pool.QueryRow(ctx, `SELECT to_regclass('public.users') IS NOT NULL AND to_regclass('public.sessions') IS NOT NULL`).Scan(&ready)
	if err != nil {
		return err
	}
	if !ready {
		return errors.New("database schema is unavailable")
	}
	return nil
}

func (s *Store) CreateUser(ctx context.Context, user User, passwordHash string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO users (id, login, name, role, password_hash) VALUES ($1,$2,$3,$4,$5)`,
		user.ID, user.Login, user.Name, user.Role, passwordHash)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "users_login_key" {
		return ErrLoginTaken
	}
	return err
}

func (s *Store) Credentials(ctx context.Context, login string) (User, string, error) {
	var user User
	var passwordHash string
	err := s.pool.QueryRow(ctx, `SELECT id::text, login, name, role, password_hash FROM users WHERE login=$1`, login).
		Scan(&user.ID, &user.Login, &user.Name, &user.Role, &passwordHash)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return user, passwordHash, err
}

func (s *Store) CreateSession(ctx context.Context, hash [32]byte, userID string, expiresAt time.Time) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO sessions (token_hash,user_id,expires_at) VALUES ($1,$2,$3)`, hash[:], userID, expiresAt)
	return err
}

func (s *Store) UserForSession(ctx context.Context, hash [32]byte, now time.Time) (User, error) {
	var user User
	err := s.pool.QueryRow(ctx, `SELECT u.id::text,u.login,u.name,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>$2`, hash[:], now).
		Scan(&user.ID, &user.Login, &user.Name, &user.Role)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return user, err
}

func (s *Store) DeleteSession(ctx context.Context, hash [32]byte) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash=$1`, hash[:])
	return err
}
