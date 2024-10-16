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
	"context"
	"regexp"
	"strings"
)

const (
	// Symlink must start with the prefix vault:// to be valid.
	vaultSymlink = `vault://`
	// Path can be anything and matches the last # as a separator of key.
	vaultSymlinkPath = `(?P<Path>.*)#`
	// Key can be any alphanumeric character and stops with the first @.
	vaultSymlinkSecret = `(?P<Secret>\w+)`
	// Version is optional and will match any number after @.
	vaultSymlinkVersion = `(@(?P<Version>\d+)?)?`
	vaultSymlinkPattern = vaultSymlink + vaultSymlinkPath + vaultSymlinkSecret + vaultSymlinkVersion
)

// isSymlink tests if secret can be converted to string and if it matches the symlink pattern.
func isSymlink(secret any) bool {
	if s, ok := secret.(string); ok {
		return strings.HasPrefix(s, vaultSymlink)
	}

	return false
}

// extractSymlinkParts extract capture group items of regex to a map.
func extractSymlinkParts(secret any) (paramsMap map[string]string) {
	r := regexp.MustCompile(vaultSymlinkPattern)
	match := r.FindStringSubmatch(secret.(string))
	paramsMap = make(map[string]string)

	for i, name := range r.SubexpNames() {
		if i > 0 && i <= len(match) {
			paramsMap[name] = match[i]
		}
	}

	return paramsMap
}

// resolveSymlink test if the data passed has symlinks and resolve them.
func (c *client) resolveSymlink(ctx context.Context, data map[string]any) (map[string]any, error) {
	for key, secret := range data {
		for isSymlink(secret) {
			symlink := extractSymlinkParts(secret)

			s, err := c.readSecret(ctx, symlink["Path"], symlink["Version"])
			if err != nil {
				return nil, err
			}

			secret = s[symlink["Secret"]]
			data[key] = secret
		}
	}

	return data, nil
}
