package vault

import (
	"context"
	"regexp"
	"strings"
)

const vaultSymlinkPattern = `vault://(?P<Path>.*)#(?P<Secret>\w+)(@(?P<Version>.*)?)?`

func isSymlink(secret any) bool {
	if s, ok := secret.(string); ok {
		return strings.HasPrefix(s, "vault://")
	}

	return false
}

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
