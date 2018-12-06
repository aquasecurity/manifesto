package registry

import (
	"strings"
	"testing"
)

func TestComputeDigest(t *testing.T) {
	const shaLen = 64
	d := computeDigest([]byte("hello world"))
	dd := strings.TrimPrefix(d, "sha256:")
	if len(dd) == len(d) {
		t.Fatalf("Digest %s didn't start with 'sha256:'", d)
	}

	if len(dd) != shaLen {
		t.Fatalf("Expected SHA to have %d chars, it's %d\n%s", shaLen, len(dd), dd)
	}
}
