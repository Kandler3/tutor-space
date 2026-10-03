package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kandler3/tutor-space/internal/auth"
)

func TestPublicHealthAndUnauthenticatedRoutes(t *testing.T) {
	app, err := New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{http.MethodGet, "/healthz", "", 200},
		{http.MethodGet, "/api/me?user_id=another-user", "", 401},
		{http.MethodPost, "/api/logout", "", 401},
		{http.MethodPost, "/api/register", `{"login":"alice","password":"long-enough-password","name":"Alice","role":"admin"}`, 400},
		{http.MethodPost, "/api/register", `{"login":"alice","password":"long-enough-password","name":"Alice","role":"student","id":"chosen-id"}`, 400},
		{http.MethodGet, "/api/homework", "", 404},
		{http.MethodGet, "/api/bookings", "", 404},
	} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		app.Handler().ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s %s status %d", tc.method, tc.path, w.Code)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("missing cache prevention")
		}
		if strings.Contains(w.Body.String(), "password_hash") {
			t.Fatal("password hash leaked")
		}
	}
}

func TestAuthorizationHeaderBoundary(t *testing.T) {
	token, expected, err := auth.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		values []string
		valid  bool
	}{
		{nil, false}, {[]string{"Bearer " + token}, true}, {[]string{"bearer " + token}, true},
		{[]string{"Basic " + token}, false}, {[]string{"Bearer fake"}, false},
		{[]string{"Bearer " + token + " extra"}, false},
		{[]string{"Bearer " + token, "Bearer " + token}, false},
	} {
		r := httptest.NewRequest(http.MethodGet, "/api/me", nil)
		for _, value := range tc.values {
			r.Header.Add("Authorization", value)
		}
		hash, valid := bearerHash(r)
		if valid != tc.valid || valid && hash != expected {
			t.Fatal("unexpected Authorization validation")
		}
	}
}

func TestAuthenticationWorkIsBounded(t *testing.T) {
	app, err := New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	app.hashingSlots <- struct{}{}
	app.hashingSlots <- struct{}{}
	r := httptest.NewRequest(http.MethodPost, "/api/register", strings.NewReader(`{"login":"alice","password":"long-enough-password","name":"Alice","role":"student"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "1" {
		t.Fatal("excess password hashing was not rejected")
	}
}
