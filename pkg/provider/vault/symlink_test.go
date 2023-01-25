package vault

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestIsSymlink(t *testing.T) {
	cases := map[string]struct {
		got  string
		want bool
	}{
		"ShouldResolveSymlink": {
			got:  "vault://test",
			want: true,
		},
		"ShouldNotResolveSymlink": {
			got:  "test",
			want: false,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, isSymlink(tc.got), EquateErrors()); diff != "" {
				t.Errorf(diff)
			}
		})
	}
}

func TestExtractSymlinkParts(t *testing.T) {
	cases := map[string]struct {
		pattern         string
		expectedPath    string
		expectedSecret  string
		expectedVersion string
	}{
		"ShouldExtractPathAndSecret": {
			pattern:         "vault://test#KEY",
			expectedPath:    "test",
			expectedSecret:  "KEY",
			expectedVersion: "",
		},
		"ShouldExtractPathAndSecretAndVersion": {
			pattern:         "vault://test#KEY@21",
			expectedPath:    "test",
			expectedSecret:  "KEY",
			expectedVersion: "21",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if diff := cmp.Diff(tc.expectedPath, extractSymlinkParts(tc.pattern)["Path"], EquateErrors()); diff != "" {
				t.Errorf(diff)
			}
			if diff := cmp.Diff(tc.expectedSecret, extractSymlinkParts(tc.pattern)["Secret"], EquateErrors()); diff != "" {
				t.Errorf(diff)
			}
			if diff := cmp.Diff(tc.expectedVersion, extractSymlinkParts(tc.pattern)["Version"], EquateErrors()); diff != "" {
				t.Errorf(diff)
			}
		})
	}
}
