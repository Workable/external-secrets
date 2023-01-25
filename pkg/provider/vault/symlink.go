package vault

import (
	"context"
	"regexp"
	"strings"
)

const (
  // Symlink must start with the prefix vault://
	vaultSymlink        = `vault://`
  // Path can be anything and matches the last # as a separator of key
	vaultSymlinkPath    = `(?P<Path>.*)#`
  // Key can be any alphanumeric character and stops with the first @
	vaultSymlinkSecret  = `(?P<Secret>\w+)`
  // Version is optional and will match any number after @
	vaultSymlinkVersion = `(@(?P<Version>\d+)?)?`
	vaultSymlinkPattern = vaultSymlink + vaultSymlinkPath + vaultSymlinkSecret + vaultSymlinkVersion
)

// isSymlink tests if secret can be converted to string and if it matches the symlink pattern
func isSymlink(secret any) bool {
	if s, ok := secret.(string); ok {
		return strings.HasPrefix(s, vaultSymlink)
	}

	return false
}

// extractSymlinkParts extract capture group items of regex to a map
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
func (v *client) resolveSymlink(ctx context.Context, data map[string]any) (map[string]any, error) {
	for key, secret := range data {
		for isSymlink(secret) {
			symlink := extractSymlinkParts(secret)

			s, err := v.readSecret(ctx, symlink["Path"], symlink["Version"])
			if err != nil {
				return nil, err
			}

			secret = s[symlink["Secret"]]
			data[key] = secret
		}
	}

	return data, nil
}
