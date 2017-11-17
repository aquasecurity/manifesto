// Package registry is a cut-down Registry V2 client for manifesto
//
// Copyright © 2017 Aqua Security Software Ltd. <info@aquasec.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package registry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh/terminal"
)

const dockerHub = "registry-1.docker.io"
const tempFileName = "_manifesto.out"
const tempContainerName = "manifesto.temp"

// AuthType is a simple int type used for enumerations of the authentication
// types supported by version 2 registries
type AuthType int

const (
	// Insecure denotes a registry with no authentication at all
	Insecure AuthType = iota
	// Token denotes a registry with token-based (OAuth2) authentication
	Token
	// Htpasswd denotes a registry with Basic HTTP authentication
	Htpasswd
)

type token string
type scope string

// V2 is the registry structure for registries supporting the V2 API
type V2 struct {
	Client   *http.Client
	URL      string
	AuthType AuthType
	Username string
	Password string
	Tokens   map[scope]token // map from scope to token
	Realm    string
	Service  string
}

type AuthChallenge struct {
	Scheme, Realm string
	Params        map[string]string
}

// MetadataManifesto gives the type of a piece of arbitrary manifesto data, and the digest where it can be found
// A given image can only have one current piece of data of each type.
// Example types might include: "seccomp", "approvals", "contact"
type MetadataManifesto struct {
	Type   string `json:"type"`
	Digest string `json:"digest"`
}

// ImageMetadataManifesto associates a piece of manifesto data with a particular image
type ImageMetadataManifesto struct {
	ImageDigest       string              `json:"image_digest"`
	MetadataManifesto []MetadataManifesto `json:"manifesto"`
}

// MetadataManifestoList holds all the metadata for a given image repository
type MetadataManifestoList struct {
	Images []ImageMetadataManifesto `json:"images"`
}

// New creates a new instance of the V2 structure for the registry located
// in the provided URL, and checks that the registry supports V2
func New(URL, username, password string) (*V2, error) {
	// make sure URL does not have a trailing slash
	URL = strings.TrimSpace(URL)
	URL = strings.TrimSuffix(URL, "/")

	// make sure URL is not empty
	if URL == "" {
		return nil, errors.New("The registry URL must be provided")
	}

	if !strings.HasPrefix(URL, "http") {
		URL = "https://" + URL
	}

	// If we don't already have a username and password, prompt for them
	if username == "" {
		fmt.Fprintf(os.Stderr, "Username: ")
		fmt.Scanf("%s", &username)
	}
	if password == "" {
		fmt.Fprintf(os.Stderr, "Password: ")
		pwd, err := terminal.ReadPassword(0)
		fmt.Fprintf(os.Stderr, "\n")
		if err != nil {
			return nil, fmt.Errorf("error reading password: %v", err)
		}
		password = string(pwd)
	}

	r := &V2{
		URL: URL,
		Client: &http.Client{
			Timeout: 10 * time.Second,
		},
		Username: username,
		Password: password,
		Tokens:   make(map[scope]token),
	}

	if username != "" {
		r.AuthType = Htpasswd
	}

	return r, nil
}

// Get is shorthand for call, without having to pass in unneeded parameters
func (r *V2) get(path string) (*http.Response, error) {
	return r.call("GET", path, []byte{}, "")
}

// call makes an HTTP request; if it fails authentication it tries to get the right authentication token
// and tries again
func (r *V2) call(method string, path string, data []byte, contentType string) (*http.Response, error) {
	// Try making the request
	res, err := r.makeRequest(method, path, data, contentType, "")
	if err != nil {
		return nil, fmt.Errorf("failed request: %v", err)
	}

	// If authorization wasn't a problem we can return
	if res.StatusCode != http.StatusUnauthorized {
		return res, nil
	}

	// If this wasn't authorized we should have a challenge describing the token we need to get
	auth, err := parseWWWAuthenticate(res.Header.Get("WWW-Authenticate"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse www-authenticate: %v", err)
	}

	// We might have a token we can try
	s, ok := auth.Params["scope"]
	if ok {
		// We know the scope, do we have a token?
		t, ok := r.Tokens[scope(s)]
		if ok {
			res, err = r.makeRequest(method, path, data, contentType, t)
			if err != nil {
				return res, fmt.Errorf("failed request with existing token: %v", err)
			}

			// If authorization wasn't a problem we can return successfully
			if res.StatusCode != http.StatusUnauthorized {
				return res, nil
			}
		}
	}

	// We didn't have the right token, or if we had a token it didn't work, perhaps because it has expired.
	t, err := r.getToken(auth)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %v", err)
	}

	// Try the call again
	res, err = r.makeRequest(method, path, data, contentType, t)
	return res, err
}

// makeRequest makes an HTTP request, setting headers and authentication
func (r *V2) makeRequest(method string, path string, data []byte, contentType string, t token) (*http.Response, error) {
	url := path
	if strings.HasPrefix(url, "/") {
		url = r.URL + path
	}

	req, err := http.NewRequest(method, url, bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}

	req.Header.Set("User-Agent", "curl")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	switch r.AuthType {
	case Htpasswd:
		req.SetBasicAuth(r.Username, r.Password)
	case Token:
		if t != "" {
			req.Header.Set("Authorization", "Bearer "+string(t))
		}
	}

	return r.Client.Do(req)
}

// AuthResponse contains the token
type AuthResponse struct {
	Token string
}

func (r *V2) getToken(auth AuthChallenge) (token, error) {
	// Construct a request for a token, using the information we parsed out of an authenticate challenge
	query := url.Values{}
	for k, v := range auth.Params {
		query.Add(k, v)
	}

	tokenURL := auth.Realm + "?" + query.Encode()
	req, err := http.NewRequest("GET", tokenURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %s", err)
	}

	req.SetBasicAuth(r.Username, r.Password)

	res, err := r.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %s", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request returned status %s", res.Status)
	}

	// Get the token out of the response
	var authRsp AuthResponse
	err = json.NewDecoder(res.Body).Decode(&authRsp)
	if err != nil {
		return "", fmt.Errorf("error decoding token response: %v", err)
	}

	s, ok := auth.Params["scope"]
	if !ok {
		return "", fmt.Errorf("no scope for token")
	}
	r.Tokens[scope(s)] = token(authRsp.Token)
	r.AuthType = Token // We'll use tokens from now on
	return token(authRsp.Token), nil
}

var authChallengeRegexp = regexp.MustCompile("^([A-Za-z0-9]+) realm=\"([^\"]+)\"(.*)")
var authParamRegexp = regexp.MustCompile(",([^=]+)=\"([^\"]+)\"")

// parseWWWAuthenticate parses the contents of a "WWW-Authenticate" HTTP header
func parseWWWAuthenticate(header string) (auth AuthChallenge, err error) {
	matches := authChallengeRegexp.FindStringSubmatch(header)

	if len(matches) < 3 {
		return auth, errors.New("Empty or invalid WWW-Authenticate header")
	}

	auth.Scheme = matches[1]
	auth.Realm = matches[2]

	if len(matches) == 4 {
		// we also have parameters, let's parse them
		auth.Params = make(map[string]string)
		paramMatches := authParamRegexp.FindAllStringSubmatch(matches[3], -1)
		for _, p := range paramMatches {
			// Each of these matches should have 3 entries
			// [0] = whole match e.g. ,service="registry.docker.io"
			// [1] = parameter name e.g. service
			// [2] = parameter value e.g. registry.docker.io
			if len(p) != 3 {
				return auth, errors.New("Failed to parse WWW-Authenticate header params")
			}
			auth.Params[p[1]] = p[2]
		}
	}

	return auth, nil
}
