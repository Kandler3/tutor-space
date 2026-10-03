package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/Kandler3/tutor-space/internal/auth"
	"github.com/Kandler3/tutor-space/internal/store"
	"github.com/Kandler3/tutor-space/migrations"
)

// Set TEST_DATABASE_URL to a separate local test database. The test applies
// migrations and cleans up only users that it created; it never truncates tables.
func TestIntegrationAuthenticationLifecycle(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set; PostgreSQL integration test skipped")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal("test database connection configuration failed")
	}
	t.Cleanup(func() { _ = db.Close() })
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.Files)
	if err != nil {
		t.Fatal("migration initialization failed")
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal("test database migration failed")
	}
	database, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal("test database connection failed")
	}
	defer database.Close()
	app, err := New(database, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	handler := app.Handler()
	request := func(method, path, body, token string, expected int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != expected {
			t.Fatalf("%s %s: status=%d, expected=%d", method, path, w.Code, expected)
		}
		if strings.Contains(w.Body.String(), "password_hash") || strings.Contains(w.Body.String(), "long-enough-integration-password") {
			t.Fatal("response leaked password material")
		}
		return w
	}
	request(http.MethodGet, "/readyz", "", "", 200)
	randomID, err := auth.NewUserID()
	if err != nil {
		t.Fatal(err)
	}
	loginPrefix := "it_" + strings.ReplaceAll(randomID[:18], "-", "")
	const password = "long-enough-integration-password"
	register := func(suffix, role string) store.User {
		t.Helper()
		w := request(http.MethodPost, "/api/register", fmt.Sprintf(`{"login":%q,"password":%q,"name":"Integration User","role":%q}`, loginPrefix+suffix, password, role), "", 201)
		var response struct {
			User store.User `json:"user"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal("cannot parse registered user")
		}
		t.Cleanup(func() {
			if _, err := db.Exec(`DELETE FROM users WHERE id=$1`, response.User.ID); err != nil {
				t.Error("cannot clean up test user")
			}
		})
		if response.User.Role != role || response.User.ID == "" {
			t.Fatal("unexpected registered profile")
		}
		return response.User
	}
	student := register("a", "student")
	otherStudent := register("b", "student")
	tutor := register("c", "tutor")
	request(http.MethodPost, "/api/register", fmt.Sprintf(`{"login":%q,"password":%q,"name":"Duplicate","role":"student"}`, student.Login, password), "", 409)
	wrong := request(http.MethodPost, "/api/login", fmt.Sprintf(`{"login":%q,"password":"incorrect-long-password"}`, student.Login), "", 401)
	unknown := request(http.MethodPost, "/api/login", fmt.Sprintf(`{"login":%q,"password":%q}`, loginPrefix+"x", password), "", 401)
	if wrong.Body.String() != unknown.Body.String() {
		t.Fatal("login failure reveals whether user exists")
	}
	login := func(user store.User) string {
		t.Helper()
		w := request(http.MethodPost, "/api/login", fmt.Sprintf(`{"login":%q,"password":%q}`, user.Login, password), "", 200)
		var response struct {
			Token     string     `json:"token"`
			TokenType string     `json:"token_type"`
			ExpiresAt time.Time  `json:"expires_at"`
			User      store.User `json:"user"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal("cannot parse login response")
		}
		if response.User.ID != user.ID || response.TokenType != "Bearer" || time.Until(response.ExpiresAt) < auth.SessionTTL-time.Minute {
			t.Fatal("incorrect login identity or expiration")
		}
		var stored []byte
		hash := sha256.Sum256([]byte(response.Token))
		if err := db.QueryRow(`SELECT token_hash FROM sessions WHERE token_hash=$1`, hash[:]).Scan(&stored); err != nil || string(stored) != string(hash[:]) {
			t.Fatal("session was not stored as a SHA-256 hash")
		}
		return response.Token
	}
	studentToken := login(student)
	tutorToken := login(tutor)
	request(http.MethodGet, "/api/me", "", "", 401)
	w := request(http.MethodGet, "/api/me?user_id="+otherStudent.ID, "", studentToken, 200)
	var me struct {
		User store.User `json:"user"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &me); err != nil || me.User.ID != student.ID {
		t.Fatal("client-supplied ID changed session identity")
	}
	request(http.MethodPost, "/api/logout", "", tutorToken, 204)
	request(http.MethodGet, "/api/me", "", tutorToken, 401)
	hash := sha256.Sum256([]byte(studentToken))
	if _, err := db.Exec(`UPDATE sessions SET expires_at=now()-interval '1 minute' WHERE token_hash=$1`, hash[:]); err != nil {
		t.Fatal("cannot expire test session")
	}
	request(http.MethodGet, "/api/me", "", studentToken, 401)
	request(http.MethodPost, "/api/logout", "", studentToken, 401)
	// Opening a new connection confirms users persist independently of a server instance.
	reopened, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal("cannot reopen test database")
	}
	defer reopened.Close()
	persisted, _, err := reopened.Credentials(ctx, student.Login)
	if err != nil || persisted.ID != student.ID {
		t.Fatal("user profile did not persist")
	}
}
