// Package grafeas allows manifesto to interact with a Grafeas server
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
// limitations under the License.package grafeas
package grafeas

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/oauth2/google"

	grafeas "github.com/Grafeas/client-go/v1alpha1"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("")

// Storage is a storage backend for metadata that uses the Grafeas API
//
// For the time being it only supports vulnerability metadata in Aqua format
// which it converts into Grafeas Notes & Occurrences.
//
// manifesto metadata type must be aqua_vulnerability_scan
type Storage struct {
	verbose bool
	projID  string
	client  *http.Client
	url     string
}

// NewStorage returns a metadata storage backend using Grafeas
func NewStorage(url string, projID string, verbose bool) *Storage {
	var err error
	var c *http.Client
	log.Debugf("Grafeas backend at %s for project %s", url, projID)

	switch os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") {
	case "":
		fmt.Printf("Set GOOGLE_APPLICATION_CREDENTIALS to the service account json file\n")
		os.Exit(1)
	case "LOCAL":
		log.Debugf("No credentials")
		c = http.DefaultClient
	default:
		c, err = google.DefaultClient(context.Background(), "https://www.googleapis.com/auth/cloud-platform")
		if err != nil {
			fmt.Printf("Error getting google API client: %v", err)
			os.Exit(1)
		}
	}

	// Test that we can access this API
	u := url + "/v1alpha1/projects/" + projID + "/occurrences"
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		log.Errorf("http request: %v", err)
		os.Exit(1)
	}

	resp, err := c.Do(req)
	if err != nil {
		log.Errorf("API error %v", err)
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK {
		log.Errorf("API Status %s", resp.Status)
		os.Exit(1)
	}

	log.Debugf("Can access API")

	return &Storage{
		verbose: verbose,
		projID:  projID,
		client:  c,
		url:     url,
	}
}

// urlForImage gets the resourceUrl for an image
func urlForImage(image string) (string, error) {
	ex := exec.Command("docker", "inspect", image, "-f", "{{.RepoDigests}}")
	digestOut, err := ex.Output()
	if err != nil {
		return "", fmt.Errorf("error reading inspect output: %v", err)
	}

	hh := strings.Split(string(digestOut), "@")
	if len(hh) < 2 {
		return "", fmt.Errorf("digest not found in %s", digestOut)
	}

	digest := strings.TrimSpace(hh[1])
	digest = strings.TrimRight(digest, "]")
	return image + ":" + digest, nil
}

// GetMetadata gets a named piece of metadata.
// Only PACKAGE_VULNERABILITY is currently supported for Grafeas backend
func (s *Storage) GetMetadata(image string, metadata string) ([]byte, string, error) {
	var data []byte
	var occurrences []grafeas.Occurrence

	if metadata != "PACKAGE_VULNERABILITY" {
		return nil, image, fmt.Errorf("metadata type must be PACKAGE_VULNERABILITY for Grafeas")
	}

	// ListOccurrences filtering on the container image URL
	u, err := urlForImage(image)
	if err != nil {
		return nil, image, err
	}

	// TODO!! Need to figure out what to do with the gcr.io prefix
	filter := "resource_url=" + u
	occurrenceRsp, err := s.listOccurrences(s.projID, filter, 0, "")
	if err != nil {
		return []byte{}, image, fmt.Errorf("list occurrences failed: %v", err)
	}

	for _, occurrence := range occurrenceRsp.Occurrences {
		log.Debugf("Occurrence for %s", occurrence.ResourceUrl)
		log.Debugf("  kind: %#v", occurrence.Kind)
		if occurrence.Kind == metadata {
			occurrences = append(occurrences, occurrence)
		}
	}

	// TODO!! Turn the occurrences list into an Aqua format report?
	data, err = json.Marshal(occurrences)
	return data, image, err
}

// ListMetadata gets a list of metadata for an image
func (s *Storage) ListMetadata(image string) ([]string, string, error) {
	metadataTypes := make(map[string]struct{}, 0)
	var metadata []string

	// ListOccurrences filtering on the container image URL
	u, err := urlForImage(image)
	if err != nil {
		return nil, image, err
	}

	// TODO!! Need to figure out what to do with the gcr.io prefix
	filter := "resource_url=" + u
	log.Debugf("Filter %s", filter)
	occurrenceRsp, err := s.listOccurrences(s.projID, filter, 0, "")
	if err != nil {
		return []string{}, image, fmt.Errorf("list occurrences failed: %v", err)
	}

	for _, occurrence := range occurrenceRsp.Occurrences {
		if _, ok := metadataTypes[occurrence.Kind]; !ok {
			metadataTypes[occurrence.Kind] = struct{}{}
		}
	}

	for k := range metadataTypes {
		metadata = append(metadata, k)
	}

	return metadata, image, nil
}

// PutMetadata stores metadata about an image
func (s *Storage) PutMetadata(image string, metadata string, dirName string) (string, error) {
	// We only support PACKAGE_VULNERABILITY for the metadata type in Grafeas
	if metadata != "PACKAGE_VULNERABILITY" {
		return image, fmt.Errorf("metadata type must be PACKAGE_VULNERABILITY for Grafeas")
	}
	image, err := s.load(dirName, "notes", s.projID)
	if err == nil {
		image, err = s.load(dirName, "occurrences", s.projID)
	}

	return image, err

}

// load reads JSON files representing Notes and Occurrences, and stores them using Grafeas
// - dirName is the parent directory (this would typically be the name of the container image)
// - objType must be either "notes" or "occurrences"
//
// load expects to find files in <dirName>/<objType>/<name>.json
// For notes the name will be taken from the <name>.
func (s *Storage) load(dirName string, objType string, projID string) (image string, err error) {
	d := filepath.Join(dirName, objType)
	if _, err := os.Stat(d); err != nil {
		return "", fmt.Errorf("no directory found at %s", d)
	}

	files, err := ioutil.ReadDir(d)
	if err != nil {
		return "", fmt.Errorf("error reading directory %s: %v", d, err)
	}

	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		b, err := ioutil.ReadFile(filepath.Join(d, f.Name()))
		if err != nil {
			return "", fmt.Errorf("error reading file %s: %v", f.Name(), err)
		}

		switch objType {
		case "notes":
			// TODO!! Should check first to see if Note already exists
			id := strings.TrimSuffix(f.Name(), ".json")
			log.Debugf("Creating note projectID %s, note name %s", projID, id)
			_, err = s.createNoteFromBytes(projID, id, b)
			if err != nil {
				return image, fmt.Errorf("create note %s failed: %v", id, err)
			}
		case "occurrences":
			// TODO!! Check that the image name in each Occurrence matches the image name we were given
			log.Debugf("Creating occurrence in projectID %s", s.projID)
			_, err = s.createOccurrenceFromBytes(s.projID, b)
			if err != nil {
				return image, fmt.Errorf("create occurrence for %s failed: %v", projID, err)
			}
		default:
			return "", fmt.Errorf("unexpected object type %s", objType)
		}
	}

	return image, nil
}
