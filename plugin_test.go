package traefik_security_txt_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	plugin "github.com/Ju0x/traefik-security-txt"
)

func TestPlugin(t *testing.T) {
	cfg := &plugin.Config{
		Contact:            []string{"mailto:test@example.test", "https://example.test/contact"},
		Expires:            "2026-12-31T23:59:00.000Z",
		Encryption:         []string{"https://example.test/pgp-key.txt"},
		Acknowledgements:   []string{"https://example.test/hall-of-fame.html"},
		PreferredLanguages: "en, de, dk",
		Policy:             []string{"https://example.test/security-policy.html", "https://bughunter.example.test/security-policy.html"},
		Hiring:             []string{"https://example.test/jobs.html"},
		CSAF:               []string{"https://example.test/.well-known/csaf/provider-metadata.json", "https://example.test/csaf/provider-metadata.json"},
	}

	expected := `Contact: mailto:test@example.test
Contact: https://example.test/contact
Expires: 2026-12-31T23:59:00.000Z
Encryption: https://example.test/pgp-key.txt
Acknowledgements: https://example.test/hall-of-fame.html
Preferred-Languages: en, de, dk
Policy: https://example.test/security-policy.html
Policy: https://bughunter.example.test/security-policy.html
Hiring: https://example.test/jobs.html
CSAF: https://example.test/.well-known/csaf/provider-metadata.json
CSAF: https://example.test/csaf/provider-metadata.json`

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := plugin.New(ctx, next, cfg, "test")
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost/.well-known/security.txt", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status code: got %v, want %v", resp.StatusCode, http.StatusOK)
	}

	body := rec.Body.String()
	if strings.TrimSpace(body) != expected {
		t.Errorf("unexpected body: got:\n%s\nwant:\n%s", body, expected)
	}
}
