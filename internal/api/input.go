package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxBodyBytes = 4096

var loginPattern = regexp.MustCompile(`^[a-z0-9_]{3,32}$`)

type registerInput struct {
	Login    string `json:"login"`
	Password string `json:"password"`
	Name     string `json:"name"`
	Role     string `json:"role"`
}

type loginInput struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

func validCredentials(login, password string) bool {
	return loginPattern.MatchString(login) && utf8.ValidString(password) && len(password) >= 12 && len(password) <= 128
}

func (in *registerInput) valid() bool {
	in.Name = strings.TrimSpace(in.Name)
	if !validCredentials(in.Login, in.Password) || !utf8.ValidString(in.Name) || utf8.RuneCountInString(in.Name) < 1 || utf8.RuneCountInString(in.Name) > 80 {
		return false
	}
	for _, r := range in.Name {
		if unicode.IsControl(r) {
			return false
		}
	}
	return in.Role == "student" || in.Role == "tutor"
}

func readJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "content_type_must_be_json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var limitError *http.MaxBytesError
		if errors.As(err, &limitError) {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large")
		} else {
			writeError(w, http.StatusBadRequest, "invalid_json")
		}
		return false
	}
	// encoding/json otherwise replaces invalid UTF-8 and accepts duplicate keys
	// and case-insensitive struct field aliases. Reject these before decoding.
	if !utf8.Valid(body) || !canonicalObject(body, target) {
		writeError(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(target)
	if err == nil {
		var extra any
		if trailingErr := decoder.Decode(&extra); trailingErr != io.EOF {
			if trailingErr == nil {
				err = errors.New("trailing JSON")
			} else {
				err = trailingErr
			}
		}
	}
	if err != nil {
		var limitError *http.MaxBytesError
		if errors.As(err, &limitError) {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large")
		} else {
			writeError(w, http.StatusBadRequest, "invalid_json")
		}
		return false
	}
	return true
}

func canonicalObject(body []byte, target any) bool {
	allowed := map[string]bool{"login": true, "password": true}
	switch target.(type) {
	case *registerInput:
		allowed["name"], allowed["role"] = true, true
	case *loginInput:
	default:
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		key, ok := token.(string)
		if !ok || !allowed[key] || seen[key] {
			return false
		}
		seen[key] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return false
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return false
	}
	var extra any
	return decoder.Decode(&extra) == io.EOF
}
