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
// limitations under the License.

package grafeas

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"

	grafeas "github.com/Grafeas/client-go/v1alpha1"
)

func (s *Storage) createNote(projectsID string, noteID string, note grafeas.Note) (*grafeas.Note, error) {
	n, err := json.Marshal(note)
	if err != nil {
		return nil, fmt.Errorf("marshalling note: %v", err)
	}

	return s.createNoteFromBytes(projectsID, noteID, n)
}

func (s *Storage) createNoteFromBytes(projectsID string, noteID string, n []byte) (*grafeas.Note, error) {
	path := s.url + "/v1alpha1/projects/" + projectsID + "/notes"

	queryParams := url.Values{}
	queryParams.Add("noteId", noteID)
	path = path + "?" + queryParams.Encode()

	log.Debugf("CreateNote at URL %s", path)
	req, err := http.NewRequest("POST", path, bytes.NewBuffer(n))
	if err != nil {
		log.Errorf("http request: %v", err)
		return nil, err
	}

	var successPayload = new(grafeas.Note)
	rsp, err := s.client.Do(req)
	if err != nil {
		return successPayload, err
	}

	b, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return successPayload, err
	}

	if rsp.StatusCode != http.StatusOK {
		log.Debugf("CreateNote response: %s %s", rsp.Status, string(b))
		return successPayload, err
	}

	err = json.Unmarshal(b, &successPayload)
	return successPayload, err
}

func (s *Storage) createOccurrence(projectsID string, occurrence grafeas.Occurrence) (*grafeas.Occurrence, error) {
	o, err := json.Marshal(occurrence)
	if err != nil {
		return nil, fmt.Errorf("marshalling occurrence: %v", err)
	}

	return s.createOccurrenceFromBytes(projectsID, o)
}

func (s *Storage) createOccurrenceFromBytes(projectsID string, o []byte) (*grafeas.Occurrence, error) {
	path := s.url + "/v1alpha1/projects/" + projectsID + "/occurrences"

	log.Debugf("CreateOccurrence at URL %s", path)
	req, err := http.NewRequest("POST", path, bytes.NewBuffer(o))
	if err != nil {
		log.Errorf("http request: %v", err)
		return nil, err
	}

	var successPayload = new(grafeas.Occurrence)
	rsp, err := s.client.Do(req)
	if err != nil {
		return successPayload, err
	}

	b, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return successPayload, err
	}

	if rsp.StatusCode != http.StatusOK {
		log.Debugf("CreateOccurrence response: %s %s", rsp.Status, string(b))
		return successPayload, err
	}

	err = json.Unmarshal(b, &successPayload)
	return successPayload, err
}

func (s *Storage) listOccurrences(projectsID string, filter string, pageSize int32, pageToken string) (*grafeas.ListOccurrencesResponse, error) {
	path := s.url + "/v1alpha1/projects/" + projectsID + "/occurrences"

	queryParams := url.Values{}
	if filter != "" {
		queryParams.Add("filter", filter)
	}
	if pageSize != 0 {
		queryParams.Add("pageSize", strconv.Itoa(int(pageSize)))
	}
	if pageToken != "" {
		queryParams.Add("pageToken", pageToken)
	}

	if len(queryParams) > 0 {
		path = path + "?" + queryParams.Encode()
	}

	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		log.Errorf("http request: %v", err)
		return nil, err
	}

	var successPayload = new(grafeas.ListOccurrencesResponse)
	rsp, err := s.client.Do(req)
	if err != nil {
		return successPayload, err
	}

	if rsp.StatusCode != http.StatusOK {
		log.Debugf("ListOccurrences response: %s %s", rsp.Status, rsp.Body)
		return successPayload, err
	}

	b, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return successPayload, err
	}

	err = json.Unmarshal(b, &successPayload)
	return successPayload, err
}

func (s *Storage) getNote(projectsID string, notesID string) (*grafeas.Note, error) {
	path := s.url + "/v1alpha1/projects/" + projectsID + "/notes/" + notesID

	log.Debugf("GetNote from URL %s", path)
	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		log.Errorf("http request: %v", err)
		return nil, err
	}

	var successPayload = new(grafeas.Note)
	rsp, err := s.client.Do(req)
	if err != nil {
		return successPayload, err
	}

	if rsp.StatusCode != http.StatusOK {
		log.Debugf("ListOccurrences response: %s %s", rsp.Status, rsp.Body)
		return successPayload, err
	}

	b, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return successPayload, err
	}

	log.Debugf("Note: %s", string(b))
	err = json.Unmarshal(b, &successPayload)
	return successPayload, err
}

func (s *Storage) listNotes(projectsID string, filter string, pageSize int32, pageToken string) (*grafeas.ListNotesResponse, error) {
	path := s.url + "/v1alpha1/projects/" + projectsID + "/notes"

	queryParams := url.Values{}
	if filter != "" {
		queryParams.Add("filter", filter)
	}
	if pageSize != 0 {
		queryParams.Add("pageSize", strconv.Itoa(int(pageSize)))
	}
	if pageToken != "" {
		queryParams.Add("pageToken", pageToken)
	}
	if len(queryParams) > 0 {
		path = path + "?" + queryParams.Encode()
	}

	log.Debugf("ListNotes from URL %s", path)
	req, err := http.NewRequest("GET", path, nil)
	if err != nil {
		log.Errorf("http request: %v", err)
		return nil, err
	}

	var successPayload = new(grafeas.ListNotesResponse)
	rsp, err := s.client.Do(req)
	if err != nil {
		return successPayload, err
	}

	if rsp.StatusCode != http.StatusOK {
		log.Debugf("ListOccurrences response: %s %s", rsp.Status, rsp.Body)
		return successPayload, err
	}

	b, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return successPayload, err
	}

	err = json.Unmarshal(b, &successPayload)
	return successPayload, err
}
