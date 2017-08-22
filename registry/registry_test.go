package registry

import "testing"

func TestParseWWWAuth(t *testing.T) {
	testcases := []struct {
		input   string
		scheme  string
		realm   string
		scope   string
		service string
	}{
		{input: "Basic realm=\"secure\"", scheme: "Basic", realm: "secure"},
		{input: "Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\",scope=\"repository:library/mongo:pull\"",
			scheme: "Bearer", realm: "https://auth.docker.io/token", service: "registry.docker.io", scope: "repository:library/mongo:pull"},
		{input: "Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\",scope=\"repository:library/mongo:push,pull\"",
			scheme: "Bearer", realm: "https://auth.docker.io/token", service: "registry.docker.io", scope: "repository:library/mongo:push,pull"},
	}

	for _, tc := range testcases {
		t.Run(tc.input, func(t *testing.T) {
			auth, err := parseWWWAuthenticate(tc.input)
			if err != nil {
				t.Fatalf("Failed but shouldn't have: %v", err)
			}
			if auth.Scheme != tc.scheme {
				t.Fatalf("Scheme: expected %s, got %s", tc.scheme, auth.Scheme)
			}
			if auth.Realm != tc.realm {
				t.Fatalf("Realm: expected %s, got %s", tc.realm, auth.Realm)
			}

			compare(t, auth, "service", tc.service)
			compare(t, auth, "scope", tc.scope)
		})
	}
}

func compare(t *testing.T, auth AuthChallenge, paramName string, expected string) {
	param, ok := auth.Params[paramName]
	if expected != "" {
		if !ok {
			t.Fatal("Params: expected to have '%s' key, did not have one", paramName)
		}
		if param != expected {
			t.Fatalf("Params.%s: expected %s, got %s", paramName, expected, param)
		}
	} else {
		if ok {
			t.Fatal("Params: didn't expect to have '%s' key", paramName)
		}
	}
}

func TestNew(t *testing.T) {
	r, err := New("example.com", "user", "pass")
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	if r.URL != "https://example.com" {
		t.Fatalf("Unexpected registry URL %s", r.URL)
	}

	if r.Username != "user" {
		t.Fatalf("Unexpected user %s", r.Username)
	}

	if r.Password != "pass" {
		t.Fatalf("Unexpected password %s", r.Password)
	}
}
