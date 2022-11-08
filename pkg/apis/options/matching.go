package options

import "net/http"

const (
	TypeDomain = "Domain"
)

// Matching is a collection of matchers between provider and domains or uris
type Matching struct {
	// ProxyRawPath will pass the raw url path to upstream allowing for url's
	// like: "/%2F/" which would otherwise be redirected to "/"
	Provider string `json:"provider"`

	// Matchers represents the configuration for the Matcher.
	Matchers []Matcher `json:"matchers,omitempty"`
}

// Matcher represents the type and the value of a matcher.
// Type can be like domain and Value then would point to some domain you want to match
type Matcher struct {
	Type string `json:"type"`

	Value string `json:"value"`
}

// Match will check the type of the matcher and executes the correct function
func Match(matcher Matcher, request *http.Request) bool {

	switch matcher.Type {
	case TypeDomain:
		return domainMatch(matcher, request.Host)
	}

	return false
}

// domainMatch will compare the value of the domain matcher with the given host and returns a bool
func domainMatch(matcher Matcher, host string) bool {
	return matcher.Value == host
}
