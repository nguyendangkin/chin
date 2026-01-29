package cmd

import (
	"strings"
)

func ensurePipExtension(path string) string {
	if strings.HasSuffix(strings.ToLower(path), ".pip") {
		return path
	}
	return path + ".pip"
}
