package traefik_security_txt

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
)

/*
	Traefik plugin to serve the security.txt defined by RFC9116 (https://datatracker.ietf.org/doc/html/rfc9116)
	Generate a security.txt here: https://securitytxt.org/
*/

var securitytxt = []byte{}

type (
	Config struct {
		Contact []string `json:"contact"`

		// Must follow ISO 8601 (for example 2026-12-31T23:59:00.000Z)
		Expires            string   `json:"expires"`
		Encryption         []string `json:"encryption,omitempty"`
		Acknowledgements   []string `json:"acknowledgements,omitempty"`
		PreferredLanguages string   `json:"preferredLanguages,omitempty"`
		// Canonical []string `json:"canonical,omitempty"`
		Policy []string `json:"policy,omitempty"`
		Hiring []string `json:"hiring,omitempty"`

		// Not defined by the RFC but available at https://securitytxt.org/, extended fields are allowed for the security.txt
		CSAF []string `json:"csaf,omitempty"`

		// TODO: Provide some method to digitally sign the security.txt
	}

	Plugin struct {
		next   http.Handler
		config *Config
	}
)

func CreateConfig() *Config {
	return &Config{}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &Plugin{
		next:   next,
		config: config,
	}, nil
}

func (p *Plugin) generateSecurityTxt() []byte {
	config := p.config

	txtFields := map[string]any{
		"Contact":             config.Contact,
		"Expires":             config.Expires,
		"Encryption":          config.Encryption,
		"Acknowledgements":    config.Acknowledgements,
		"Preferred-Languages": config.PreferredLanguages,
		"Policy":              config.Policy,
		"Hiring":              config.Hiring,
		"CSAF":                config.CSAF,
	}

	order := []string{"Contact", "Expires", "Encryption", "Acknowledgements", "Preferred-Languages", "Policy", "Hiring", "CSAF"}

	var buf bytes.Buffer
	for _, key := range order {
		val, ok := txtFields[key]
		if !ok || val == nil {
			continue
		}

		// Check whether its a list or a string and add the fields according to their datatype
		switch v := val.(type) {
		case string:
			if v != "" {
				fmt.Fprintf(&buf, "%s: %s\n", key, v)
			}
		case []string:
			for _, s := range v {
				if s != "" {
					fmt.Fprintf(&buf, "%s: %s\n", key, s)
				}
			}
		}
	}

	return buf.Bytes()
}

func (p *Plugin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.ToLower(r.URL.Path)

	// Security.txt should be placed in /.well-known/security.txt as default but the root directory can also be used as a fallback.
	// We use both paths to ensure that the file is found.
	if path == "/security.txt" || path == "/.well-known/security.txt" {
		w.Header().Set("Content-Type", "text/plain")

		if len(securitytxt) == 0 {
			securitytxt = p.generateSecurityTxt()
		}

		w.Write(securitytxt)
		return
	}

	p.next.ServeHTTP(w, r)
}
