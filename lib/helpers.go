package lib

import "strings"

func StringPtr(s string) *string { return &s }

func IntPtr(i int) *int { return &i }

func BoolPtr(b bool) *bool { return &b }

func ParseTags(tags string) []string {
	if tags == "" {
		return make([]string, 0)
	}

	var tagList = strings.Split(tags, ",")
	for i, tag := range tagList {
		tagList[i] = strings.TrimSpace(tag)
	}

	return tagList
}
