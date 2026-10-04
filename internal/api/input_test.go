package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestJSONBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, body, contentType string
		status                  int
	}{
		{"valid", `{"login":"alice","password":"long-password"}`, "application/json", 200},
		{"unknown", `{"login":"alice","password":"long-password","user_id":"other"}`, "application/json", 400},
		{"trailing_object", `{"login":"alice"} {}`, "application/json", 400},
		{"trailing_garbage", `{"login":"alice"}broken`, "application/json", 400},
		{"empty", "", "application/json", 400},
		{"array", `[]`, "application/json", 400},
		{"wrong_type", `{"password":123}`, "application/json", 400},
		{"duplicate_key", `{"login":"alice","login":"bob","password":"long-password"}`, "application/json", 400},
		{"case_alias", `{"Login":"alice","password":"long-password"}`, "application/json", 400},
		{"invalid_utf8_body", "{\"login\":\"alice\",\"password\":\"long-password-\xff\"}", "application/json", 400},
		{"null", `null`, "application/json", 400},
		{"large", `{"login":"alice","password":"` + strings.Repeat("x", maxBodyBytes) + `"}`, "application/json", 413},
		{"media_type", `{}`, "text/plain", 415},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", tc.contentType)
			w := httptest.NewRecorder()
			var in loginInput
			valid := readJSON(w, r, &in)
			if valid != (tc.status == 200) || w.Code != tc.status {
				t.Fatalf("got accepted=%v, status=%d", valid, w.Code)
			}
		})
	}
}

func TestRegistrationBoundary(t *testing.T) {
	base := registerInput{Login: "alice_1", Password: "long-enough-password", Name: " Алиса ", Role: "student"}
	if !base.valid() || base.Name != "Алиса" {
		t.Fatal("valid Unicode name was rejected or not trimmed")
	}
	for _, tc := range []struct {
		name   string
		modify func(*registerInput)
	}{
		{"admin", func(in *registerInput) { in.Role = "admin" }},
		{"uppercase_login", func(in *registerInput) { in.Login = "Alice" }},
		{"sql_login", func(in *registerInput) { in.Login = "x' OR 1=1 --" }},
		{"short_login", func(in *registerInput) { in.Login = "ab" }},
		{"long_login", func(in *registerInput) { in.Login = strings.Repeat("a", 33) }},
		{"short_password", func(in *registerInput) { in.Password = "short" }},
		{"long_password", func(in *registerInput) { in.Password = strings.Repeat("x", 129) }},
		{"invalid_utf8_password", func(in *registerInput) { in.Password = "long-password-\xff" }},
		{"empty_name", func(in *registerInput) { in.Name = "  " }},
		{"long_name", func(in *registerInput) { in.Name = strings.Repeat("Я", 81) }},
		{"control_name", func(in *registerInput) { in.Name = "Alice\nBob" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			tc.modify(&in)
			if in.valid() {
				t.Fatal("invalid input accepted")
			}
		})
	}
}
