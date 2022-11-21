package options

import (
	"net/http"
	"regexp"
)

type Cors struct {
	Credentials    bool
	AllowedHeaders []string
	AllowedOrigins []string
}

func corsDefault() Cors {
	return Cors{
		Credentials: false,
	}
}

func (o *AlphaOptions) IsOriginAllowed(req *http.Request) string {
	allowedOriginsLen := len(o.Server.Cors.AllowedOrigins)

	// if there are no origins and we have with credentials return nothing
	if allowedOriginsLen == 0 && o.Server.Cors.Credentials {
		return ""
	}

	// if there are no allowed Origins and credentials are false then return asterisk
	if allowedOriginsLen == 0 && !o.Server.Cors.Credentials {
		return "*"
	}

	// if we have allowed origins we need to check for regex
	if allowedOriginsLen > 0 {
		// first we check if the one configured is an asterisk, if so we just return it
		if o.Server.Cors.AllowedOrigins[0] == "*" {
			return "*"
		}

		for _, allowedOrigin := range o.Server.Cors.AllowedOrigins {
			re := regexp.MustCompile(allowedOrigin)

			if len(re.FindStringIndex(req.Header.Get("Origin"))) > 0 {
				return req.Header.Get("Origin")
			}
		}
	}
	return ""
}
