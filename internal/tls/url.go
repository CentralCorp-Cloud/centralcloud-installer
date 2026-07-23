package tls

import "net/url"

type urlAlias url.URL

func parseSPIFFE(value string) (*urlAlias, error) {
	parsed, err := url.Parse(value)
	return (*urlAlias)(parsed), err
}

func aliasURLs(values []*urlAlias) []*url.URL {
	result := make([]*url.URL, 0, len(values))
	for _, value := range values {
		result = append(result, (*url.URL)(value))
	}
	return result
}
