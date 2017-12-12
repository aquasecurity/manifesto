package grafeas

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndPutMetadata(t *testing.T) {
	dir := "temptest"
	err := os.Mkdir(dir, 0777)
	if err != nil {
		t.Fatalf("Can't create temp dir")
	}
	defer os.RemoveAll(dir)
	fmt.Printf("temp dir is %s\n", dir)

	oPath := filepath.Join(dir, "occurrences")
	if err := os.Mkdir(oPath, 0777); err != nil {
		t.Fatalf("mkdir %s %v", oPath, err)
	}
	nPath := filepath.Join(dir, "notes")
	if err := os.Mkdir(nPath, 0777); err != nil {
		t.Fatalf("mkdir %s %v", nPath, err)
	}

	occurrences := tempOccurrences("lizrice/hello:1")
	b, err := json.Marshal(occurrences[0])
	oFile := filepath.Join(oPath, "occurrence1.json")
	fmt.Printf("writing file at %s\n", oFile)
	if err := ioutil.WriteFile(oFile, b, 0666); err != nil {
		log.Fatal(err)
	}

	notes := tempNotes("lizrice/hello:1")
	b, err = json.Marshal(notes[0])
	nFile := filepath.Join(nPath, "note1.json")
	if err := ioutil.WriteFile(nFile, b, 0666); err != nil {
		log.Fatal(err)
	}

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"name": "test"}`))
		}))

	defer server.Close()
	s := &Storage{
		projID: "testProjID",
		url:    server.URL,
		client: http.DefaultClient,
	}

	_, err = s.PutMetadata("lizrice/hello:1", "PACKAGE_VULNERABILITY", dir)
	if err != nil {
		t.Fatalf("%v", err)
	}
}
