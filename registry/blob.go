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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

func computeDigest(data []byte) string {
	hasher := sha256.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)
	return "sha256:" + hex.EncodeToString(digest)
}

// UploadBlob pushes a blob of data to the registry
func (r *V2) UploadBlob(repoName string, data io.Reader) (string, error) {

	// Post to get the location / UUID for this upload
	URL := "/v2/" + repoName + "/blobs/uploads/"
	res, err := r.call("POST", URL, []byte{}, "")
	if err != nil {
		return "", fmt.Errorf("post to %s failed: %v", URL, err)
	}

	// We don't need the body at all so discard and close it now
	io.Copy(ioutil.Discard, res.Body)
	res.Body.Close()

	if res.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("post to %s not accepted: %s", URL, res.Status)
	}

	// The post gives us the location for the blob upload
	location := res.Header.Get("Location")

	// Read the data so we can calculate its digest
	b, err := ioutil.ReadAll(data)
	if err != nil {
		return "", fmt.Errorf("couldn't read data: %v", err)
	}

	digest := computeDigest(b)
	if strings.Contains(location, "?") {
		location += ("&digest=" + digest)
	} else {
		location += ("?digest=" + digest)
	}

	// Upload the data monolithically
	res, err = r.call("PUT", location, b, "application/octet-stream")
	if err != nil {
		return "", fmt.Errorf("upload blob failed: %v", err)
	}

	io.Copy(ioutil.Discard, res.Body)
	res.Body.Close()

	if res.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("unexpected upload status: %s", res.Status)
	}

	return digest, nil
}

// GetBlob downloads a blob specified by repo name and digest
func (r *V2) GetBlob(repoName string, digest string) ([]byte, error) {
	res, err := r.get("/v2/" + repoName + "/blobs/" + digest)
	if err != nil {
		return []byte{}, fmt.Errorf("get blob failed: %v", err)
	}

	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		io.Copy(ioutil.Discard, res.Body)
		return []byte{}, fmt.Errorf("unexpected get blob status: %s", res.Status)
	}

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return []byte{}, fmt.Errorf("error reading get blob: %v", err)
	}

	return data, nil
}
