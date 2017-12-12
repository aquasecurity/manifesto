// TEMPORARILY FAKE SOME DATA
package grafeas

import (
	"net/http"
	"net/http/httptest"
	"testing"

	grafeas "github.com/Grafeas/client-go/v1alpha1"
)

func TestCreateNote(t *testing.T) {
	tests := []struct {
		name     string
		URL      string
		method   string
		response string
	}{
		{
			name:     "createNote",
			URL:      "/v1alpha1/projects/testProjID/notes?noteId=testNoteID",
			method:   "POST",
			response: `{ "name": "projects/aqua-scan/notes/CVE-2014-9911"}`,
		},
		{
			name:     "createOccurrence",
			URL:      "/v1alpha1/projects/testProjID/occurrences",
			method:   "POST",
			response: `{ "name": "projects/aqua-scan/occurrences/12345"}`,
		},
		{
			name:     "getNote",
			URL:      "/v1alpha1/projects/testProjID/notes/testNoteID",
			method:   "GET",
			response: `{ "name": "projects/aqua-scan/notes/CVE-2014-9911"}`,
		},
		{
			name:     "listOccurrences",
			URL:      "/v1alpha1/projects/testProjID/occurrences",
			method:   "GET",
			response: `{}`,
		},
		{
			name:   "listOccurrences1",
			URL:    "/v1alpha1/projects/testProjID/occurrences?filter=x%3Dy",
			method: "GET",
			response: `{"occurrences": [
				{ "name": "hello" }
			]}`,
		},
		{
			name:     "listNotes",
			URL:      "/v1alpha1/projects/testProjID/notes",
			method:   "GET",
			response: `{}`,
		},
		{
			name:   "listNotes1",
			URL:    "/v1alpha1/projects/testProjID/notes?filter=x%3Dy",
			method: "GET",
			response: `{"notes": [
				{ "name": "hello" }
			]}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t.Logf("%s", r.URL)
					if r.URL.String() != test.URL {
						t.Fatalf("Unexpected URL %s\nexpected %s", r.URL.String(), test.URL)
					}
					if r.Method != test.method {
						t.Fatalf("Unexpected Method %s expected %s", r.Method, test.method)
					}
					w.Write([]byte(test.response))
				}))

			defer server.Close()
			s := &Storage{
				projID: "testProjID",
				url:    server.URL,
				client: http.DefaultClient,
			}

			switch test.name {
			case "createNote":
				notes := tempNotes("lizrice/hello:1")
				n, err := s.createNote("testProjID", "testNoteID", notes[0])
				if err != nil {
					t.Fatalf("%v", err)
				}
				if n.Name != "projects/aqua-scan/notes/CVE-2014-9911" {
					t.Fatalf("Unexpected name: %s", n.Name)
				}
			case "createOccurrence":
				occurrences := tempOccurrences("lizrice/hello:1")
				o, err := s.createOccurrence("testProjID", occurrences[0])
				if err != nil {
					t.Fatalf("%v", err)
				}
				if o.Name != "projects/aqua-scan/occurrences/12345" {
					t.Fatalf("Unexpected name: %s", o.Name)
				}
			case "getNote":
				n, err := s.getNote("testProjID", "testNoteID")
				if err != nil {
					t.Fatalf("%v", err)
				}
				if n.Name != "projects/aqua-scan/notes/CVE-2014-9911" {
					t.Fatalf("Unexpected name: %s", n.Name)
				}
			case "getOccurrence":
				t.Fatalf("Not implemented")
			case "listOccurrences":
				l, err := s.listOccurrences("testProjID", "", 0, "")
				if err != nil {
					t.Fatalf("%v", err)
				}
				if len(l.Occurrences) > 0 {
					t.Fatalf("Unexpected occurrences")
				}
			case "listOccurrences1":
				l, err := s.listOccurrences("testProjID", "x=y", 0, "")
				if err != nil {
					t.Fatalf("%v", err)
				}
				if len(l.Occurrences) != 1 {
					t.Fatalf("Unexpected occurrences")
				}
				if l.Occurrences[0].Name != "hello" {
					t.Fatalf("Unexpected name %s", l.Occurrences[0].Name)
				}
			case "listNotes":
				l, err := s.listNotes("testProjID", "", 0, "")
				if err != nil {
					t.Fatalf("%v", err)
				}
				if len(l.Notes) > 0 {
					t.Fatalf("Unexpected notes")
				}
			case "listNotes1":
				l, err := s.listNotes("testProjID", "x=y", 0, "")
				if err != nil {
					t.Fatalf("%v", err)
				}
				if len(l.Notes) != 1 {
					t.Fatalf("Unexpected notes")
				}
				if l.Notes[0].Name != "hello" {
					t.Fatalf("Unexpected name %s", l.Notes[0].Name)
				}
			}
		})
	}
}

func tempOccurrences(image string) []grafeas.Occurrence {

	occurrence0 := grafeas.Occurrence{
		ResourceUrl: "registry-1.docker.io/lizrice/hello@sha256:fb19fad1d75d467310fb4962787431acfecf17a32b29cd64d7d586c547446ba5",
		NoteName:    "projects/aqua-scan/notes/CVE-2014-9911",
		Kind:        "PACKAGE_VULNERABILITY",
		VulnerabilityDetails: grafeas.VulnerabilityDetails{
			Severity:  "HIGH",
			CvssScore: 7.5,
			PackageIssue: []grafeas.PackageIssue{
				grafeas.PackageIssue{
					SeverityName: "HIGH",
					AffectedLocation: grafeas.VulnerabilityLocation{
						CpeUri:   "cpe:/o:debian:debian_linux:8",
						Package_: "icu",
						Version: grafeas.Version{
							Name:     "52.1",
							Revision: "8+deb8u3",
						},
					},
					FixedLocation: grafeas.VulnerabilityLocation{
						CpeUri:   "cpe:/o:debian:debian_linux:8",
						Package_: "icu",
						Version: grafeas.Version{
							Name:     "52.1",
							Revision: "8+deb8u4",
						},
					},
				},
			},
		},
	}

	occurrence1 := grafeas.Occurrence{
		ResourceUrl: "registry-1.docker.io/lizrice/hello@sha256:2a1b47e618e712fd95680091cac56468a9e7e2fe60bf4224fbea3613f4a64cea",
		NoteName:    "projects/aqua-scan/notes/CVE-2014-9911",
		Kind:        "PACKAGE_VULNERABILITY",
		VulnerabilityDetails: grafeas.VulnerabilityDetails{
			Severity:  "HIGH",
			CvssScore: 7.5,
			PackageIssue: []grafeas.PackageIssue{
				grafeas.PackageIssue{
					SeverityName: "HIGH",
					AffectedLocation: grafeas.VulnerabilityLocation{
						CpeUri:   "cpe:/o:debian:debian_linux:8",
						Package_: "icu",
						Version: grafeas.Version{
							Name:     "52.1",
							Revision: "8+deb8u3",
						},
					},
					FixedLocation: grafeas.VulnerabilityLocation{
						CpeUri:   "cpe:/o:debian:debian_linux:8",
						Package_: "icu",
						Version: grafeas.Version{
							Name:     "52.1",
							Revision: "8+deb8u4",
						},
					},
				},
			},
		},
	}

	occurrence2 := grafeas.Occurrence{
		ResourceUrl: "registry-1.docker.io/lizrice/hello@sha256:2a1b47e618e712fd95680091cac56468a9e7e2fe60bf4224fbea3613f4a64cea",
		NoteName:    "projects/aqua-scan/notes/CVE-2017-I-made-this-up",
		Kind:        "PACKAGE_VULNERABILITY",
		VulnerabilityDetails: grafeas.VulnerabilityDetails{
			Severity:  "HIGH",
			CvssScore: 7.5,
			PackageIssue: []grafeas.PackageIssue{
				grafeas.PackageIssue{
					SeverityName: "HIGH",
					AffectedLocation: grafeas.VulnerabilityLocation{
						CpeUri:   "cpe:/o:debian:debian_linux:8",
						Package_: "icu",
						Version: grafeas.Version{
							Name:     "52.1",
							Revision: "8+deb8u3",
						},
					},
					FixedLocation: grafeas.VulnerabilityLocation{
						CpeUri:   "cpe:/o:debian:debian_linux:8",
						Package_: "icu",
						Version: grafeas.Version{
							Name:     "52.1",
							Revision: "8+deb8u4",
						},
					},
				},
			},
		},
	}

	switch image {
	case "lizrice/hello:1":
		return []grafeas.Occurrence{occurrence0}
	case "lizrice/hello:2":
		return []grafeas.Occurrence{occurrence1, occurrence2}
	}

	return []grafeas.Occurrence{}
}

func tempNotes(image string) []grafeas.Note {
	note0 := grafeas.Note{
		Name:             "projects/aqua-scan/notes/CVE-2014-9911",
		ShortDescription: "CVE-2014-9911",
		LongDescription:  "NIST vectors: AV:N/AC:L/Au:N/C:P/I:P",
		Kind:             "PACKAGE_VULNERABILITY",
		VulnerabilityType: grafeas.VulnerabilityType{
			CvssScore: 7.5,
			Severity:  "HIGH",
			Details: []grafeas.Detail{
				{
					CpeUri:   "cpe:/o:debian:debian_linux:7",
					Package_: "icu",
					Description: "Stack-based buffer overflow in the ures_getByKeyWithFallback function in " +
						"common/uresbund.cpp in International Components for Unicode (ICU) before 54.1 for C/C++ allows " +
						"remote attackers to cause a denial of service or possibly have unspecified other impact via a crafted uloc_getDisplayName call.",
					MinAffectedVersion: grafeas.Version{
						Kind: "MINIMUM",
					},
					SeverityName: "HIGH",

					FixedLocation: grafeas.VulnerabilityLocation{
						CpeUri:   "cpe:/o:debian:debian_linux:7",
						Package_: "icu",
						Version: grafeas.Version{
							Name:     "4.8.1.1",
							Revision: "12+deb7u6",
						},
					},
				},
				{
					CpeUri:   "cpe:/o:debian:debian_linux:8",
					Package_: "icu",
					Description: "Stack-based buffer overflow in the ures_getByKeyWithFallback function in " +
						"common/uresbund.cpp in International Components for Unicode (ICU) before 54.1 for C/C++ allows " +
						"remote attackers to cause a denial of service or possibly have unspecified other impact via a crafted uloc_getDisplayName call.",
					MinAffectedVersion: grafeas.Version{
						Kind: "MINIMUM",
					},
					SeverityName: "HIGH",

					FixedLocation: grafeas.VulnerabilityLocation{
						CpeUri:   "cpe:/o:debian:debian_linux:8",
						Package_: "icu",
						Version: grafeas.Version{
							Name:     "52.1",
							Revision: "8+deb8u4",
						},
					},
				},
				{
					CpeUri:   "cpe:/o:debian:debian_linux:9",
					Package_: "icu",
					Description: "Stack-based buffer overflow in the ures_getByKeyWithFallback function in " +
						"common/uresbund.cpp in International Components for Unicode (ICU) before 54.1 for C/C++ allows " +
						"remote attackers to cause a denial of service or possibly have unspecified other impact via a crafted uloc_getDisplayName call.",
					MinAffectedVersion: grafeas.Version{
						Kind: "MINIMUM",
					},
					SeverityName: "HIGH",

					FixedLocation: grafeas.VulnerabilityLocation{
						CpeUri:   "cpe:/o:debian:debian_linux:9",
						Package_: "icu",
						Version: grafeas.Version{
							Name:     "55.1",
							Revision: "3",
						},
					},
				},
				{
					CpeUri:   "cpe:/o:canonical:ubuntu_linux:14.04",
					Package_: "andriod",
					Description: "Stack-based buffer overflow in the ures_getByKeyWithFallback function in " +
						"common/uresbund.cpp in International Components for Unicode (ICU) before 54.1 for C/C++ allows " +
						"remote attackers to cause a denial of service or possibly have unspecified other impact via a crafted uloc_getDisplayName call.",
					MinAffectedVersion: grafeas.Version{
						Kind: "MINIMUM",
					},
					SeverityName: "MEDIUM",

					FixedLocation: grafeas.VulnerabilityLocation{
						CpeUri:   "cpe:/o:canonical:ubuntu_linux:14.04",
						Package_: "andriod",
						Version: grafeas.Version{
							Kind: "MAXIMUM",
						},
					},
				},
			},
		},
		RelatedUrl: []grafeas.RelatedUrl{
			{
				Url:   "https://security-tracker.debian.org/tracker/CVE-2014-9911",
				Label: "More Info",
			},
			{
				Url:   "http://people.ubuntu.com/~ubuntu-security/cve/CVE-2014-9911",
				Label: "More Info",
			},
		},
	}

	note1 := grafeas.Note{
		// Name:             "projects/aqua-scan/notes/CVE-2017-I-made-this-up",
		ShortDescription: "CVE-2017-I-made-this-up",
		LongDescription:  "NIST vectors: AV:N/AC:L/Au:N/C:P/I:P",
		Kind:             "PACKAGE_VULNERABILITY",
		VulnerabilityType: grafeas.VulnerabilityType{
			CvssScore: 7.5,
			Severity:  "HIGH",
			Details: []grafeas.Detail{
				{
					CpeUri:   "cpe:/o:debian:debian_linux:7",
					Package_: "icu",
					Description: "Stack-based buffer overflow in the ures_getByKeyWithFallback function in " +
						"common/uresbund.cpp in International Components for Unicode (ICU) before 54.1 for C/C++ allows " +
						"remote attackers to cause a denial of service or possibly have unspecified other impact via a crafted uloc_getDisplayName call.",
					MinAffectedVersion: grafeas.Version{
						Kind: "MINIMUM",
					},
					SeverityName: "HIGH",

					FixedLocation: grafeas.VulnerabilityLocation{
						CpeUri:   "cpe:/o:debian:debian_linux:7",
						Package_: "icu",
						Version: grafeas.Version{
							Name:     "4.8.1.1",
							Revision: "12+deb7u6",
						},
					},
				},
				{
					CpeUri:   "cpe:/o:debian:debian_linux:8",
					Package_: "icu",
					Description: "Stack-based buffer overflow in the ures_getByKeyWithFallback function in " +
						"common/uresbund.cpp in International Components for Unicode (ICU) before 54.1 for C/C++ allows " +
						"remote attackers to cause a denial of service or possibly have unspecified other impact via a crafted uloc_getDisplayName call.",
					MinAffectedVersion: grafeas.Version{
						Kind: "MINIMUM",
					},
					SeverityName: "HIGH",

					FixedLocation: grafeas.VulnerabilityLocation{
						CpeUri:   "cpe:/o:debian:debian_linux:8",
						Package_: "icu",
						Version: grafeas.Version{
							Name:     "52.1",
							Revision: "8+deb8u4",
						},
					},
				},
			},
		},
		RelatedUrl: []grafeas.RelatedUrl{
			{
				Url:   "https://security-tracker.debian.org/tracker/CVE-2017-I-made-this-up",
				Label: "More Info",
			},
			{
				Url:   "http://people.ubuntu.com/~ubuntu-security/cve/CVE-2017-I-made-this-up",
				Label: "More Info",
			},
		},
	}

	switch image {
	case "lizrice/hello:1":
		return []grafeas.Note{note0}
	case "lizrice/hello:2":
		return []grafeas.Note{note0, note1}
	}

	return []grafeas.Note{}
}
