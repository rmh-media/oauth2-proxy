package options

import (
	"net/http"
	"regexp"
)

const (
	TypeDomain = "Domain"
	TypeRegex  = "Regex"
)

// Matching is a collection of matchers between provider and domains or uris
type Matching struct {
	// Provider is the id of the configured provider
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
	case TypeRegex:
		return regexMatch(matcher, request.Host)
	}

	return false
}

// domainMatch will compare the value of the domain matcher with the given host and returns a bool
func domainMatch(matcher Matcher, host string) bool {
	return matcher.Value == host
}

// regexMatch will do a simple regex match on the given regex and the host
func regexMatch(matcher Matcher, host string) bool {
	re := regexp.MustCompile(matcher.Value)

	if len(re.FindStringIndex(host)) > 0 {
		return true
	}
	return false
}
