package registry

import "testing"

func TestGetNameComponents(t *testing.T) {
	cases := []struct {
		input      string
		reg        string
		repo       string
		img        string
		repoNoHost string
		tag        string
		digest     string
	}{
		{"lizrice/imagetest", "registry-1.docker.io", "lizrice/imagetest", "lizrice/imagetest:latest", "lizrice/imagetest", "latest", ""},
		{"lizrice/imagetest:v1.0", "registry-1.docker.io", "lizrice/imagetest", "lizrice/imagetest:v1.0", "lizrice/imagetest", "v1.0", ""},
		{"quay.io/lizrice/imagetest:v1.0", "quay.io", "quay.io/lizrice/imagetest", "quay.io/lizrice/imagetest:v1.0", "lizrice/imagetest", "v1.0", ""},
		{"localhost:5000/lizrice/imagetest:v1.0", "localhost:5000", "localhost:5000/lizrice/imagetest", "localhost:5000/lizrice/imagetest:v1.0", "lizrice/imagetest", "v1.0", ""},
		{"lizrice/imagetest@12345", "registry-1.docker.io", "lizrice/imagetest", "lizrice/imagetest:latest", "lizrice/imagetest", "latest", "12345"},
	}

	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			reg, repo, img, repoNoHost, tag, digest := getNameComponents(c.input)
			if reg != c.reg {
				t.Fatalf("registry name: got %s expected %s", reg, c.reg)
			}
			if repo != c.repo {
				t.Fatalf("repo name: got %s expected %s", repo, c.repo)
			}
			if img != c.img {
				t.Fatalf("image name: got %s expected %s", img, c.img)
			}
			if repoNoHost != c.repoNoHost {
				t.Fatalf("repo name without host: got %s expected %s", repoNoHost, c.repoNoHost)
			}
			if tag != c.tag {
				t.Fatalf("tag name: got %s expected %s", tag, c.tag)
			}
			if digest != c.digest {
				t.Fatalf("digest: got %s expected %s", digest, c.digest)
			}
		})
	}
}

func TestImageNameForManifest(t *testing.T) {
	cases := []struct {
		input string
		img   string
	}{
		{"lizrice/imagetest", "lizrice/imagetest:_manifesto"},
		{"lizrice/imagetest:v1.0", "lizrice/imagetest:_manifesto"},
		{"quay.io/lizrice/imagetest:v1.0", "quay.io/lizrice/imagetest:_manifesto"},
		{"localhost:5000/lizrice/imagetest", "localhost:5000/lizrice/imagetest:_manifesto"},
	}

	for _, c := range cases {
		t.Run(c.input, func(t *testing.T) {
			_, repo, _, _, _, _ := getNameComponents(c.input)
			img := imageNameForManifest(repo)
			if img != c.img {
				t.Fatalf("manifesto image name: got %s expected %s", img, c.img)
			}
		})
	}
}
