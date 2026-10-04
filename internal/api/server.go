package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Kandler3/tutor-space/internal/auth"
	"github.com/Kandler3/tutor-space/internal/store"
)

type Server struct {
	store             *store.Store
	logger            *slog.Logger
	dummyPasswordHash string
	hashingSlots      chan struct{}
}

func New(database *store.Store, logger *slog.Logger) (*Server, error) {
	dummyHash, err := auth.HashPassword("dummy-password-for-unknown-login")
	if err != nil {
		return nil, err
	}
	return &Server{store: database, logger: logger, dummyPasswordHash: dummyHash, hashingSlots: make(chan struct{}, 2)}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("POST /api/register", s.register)
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("GET /api/me", s.me)
	mux.HandleFunc("POST /api/logout", s.logout)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		mux.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ready(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var in registerInput
	if !readJSON(w, r, &in) {
		return
	}
	if !in.valid() {
		writeError(w, http.StatusBadRequest, "invalid_registration")
		return
	}
	if !s.acquireHashing(w) {
		return
	}
	defer s.releaseHashing()
	passwordHash, err := auth.HashPassword(in.Password)
	if err != nil {
		s.internalError(w, "hash_password")
		return
	}
	id, err := auth.NewUserID()
	if err != nil {
		s.internalError(w, "generate_user_id")
		return
	}
	user := store.User{ID: id, Login: in.Login, Name: in.Name, Role: in.Role}
	if err := s.store.CreateUser(r.Context(), user, passwordHash); err != nil {
		if errors.Is(err, store.ErrLoginTaken) {
			writeError(w, http.StatusConflict, "login_unavailable")
		} else {
			s.internalError(w, "create_user")
		}
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user": user})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in loginInput
	if !readJSON(w, r, &in) {
		return
	}
	if !validCredentials(in.Login, in.Password) {
		writeError(w, http.StatusBadRequest, "invalid_credentials_format")
		return
	}
	if !s.acquireHashing(w) {
		return
	}
	defer s.releaseHashing()
	user, passwordHash, err := s.store.Credentials(r.Context(), in.Login)
	unknownUser := errors.Is(err, store.ErrNotFound)
	if err != nil && !unknownUser {
		s.internalError(w, "read_credentials")
		return
	}
	if unknownUser {
		passwordHash = s.dummyPasswordHash
	}
	valid, err := auth.VerifyPassword(in.Password, passwordHash)
	if err != nil {
		s.internalError(w, "verify_password")
		return
	}
	if !valid || unknownUser {
		writeError(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	token, tokenHash, err := auth.NewSessionToken()
	if err != nil {
		s.internalError(w, "generate_session")
		return
	}
	expiresAt := time.Now().UTC().Add(auth.SessionTTL)
	if err := s.store.CreateSession(r.Context(), tokenHash, user.ID, expiresAt); err != nil {
		s.internalError(w, "create_session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "token_type": "Bearer", "expires_at": expiresAt, "user": user})
}

func bearerHash(r *http.Request) ([32]byte, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return [32]byte{}, false
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return [32]byte{}, false
	}
	return auth.TokenHash(parts[1])
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (store.User, [32]byte, bool) {
	hash, valid := bearerHash(r)
	if !valid {
		unauthorized(w)
		return store.User{}, [32]byte{}, false
	}
	user, err := s.store.UserForSession(r.Context(), hash, time.Now().UTC())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			unauthorized(w)
		} else {
			s.internalError(w, "read_session")
		}
		return store.User{}, [32]byte{}, false
	}
	return user, hash, true
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	user, _, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	_, hash, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteSession(r.Context(), hash); err != nil {
		s.internalError(w, "delete_session")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) acquireHashing(w http.ResponseWriter) bool {
	select {
	case s.hashingSlots <- struct{}{}:
		return true
	default:
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusServiceUnavailable, "authentication_busy")
		return false
	}
}

func (s *Server) releaseHashing() { <-s.hashingSlots }

func (s *Server) internalError(w http.ResponseWriter, operation string) {
	// Driver errors can contain connection details; never log raw errors,
	// credentials, request bodies or Authorization headers.
	s.logger.Error("request failed", "operation", operation)
	writeError(w, http.StatusInternalServerError, "internal_error")
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeError(w, http.StatusUnauthorized, "unauthorized")
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
