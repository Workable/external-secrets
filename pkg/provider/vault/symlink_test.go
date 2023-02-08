/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
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
