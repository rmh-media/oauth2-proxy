package options

import (
	ipapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/ip"
	internaloidc "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/oidc"
	"net/url"
	"time"
)

// Server represents the configuration for an HTTP(S) server
type Server struct {
	// BindAddress is the address on which to serve traffic.
	// Leave blank or set to "-" to disable.
	BindAddress string

	// SecureBindAddress is the address on which to serve secure traffic.
	// Leave blank or set to "-" to disable.
	SecureBindAddress string

	// TLS contains the information for loading the certificate and key for the
	// secure traffic and further configuration for the TLS server.
	TLS *TLS

	ProxyPrefix        string
	ReverseProxy       bool
	TrustedIPs         []string
	RealClientIPHeader string
	ForceHTTPS         bool
	PingPath           string
	PingUserAgent      string

	AuthenticatedEmailsFile string
	EmailDomains            []string
	HtpasswdFile            string
	HtpasswdUserGroups      []string

	Cookie    CookieOptions `json:"cookie,omitempty"`
	Session   SessionOptions
	Logging   Logging
	Templates Templates

	RawRedirectURL string `json:"redirectUrl"`

	APIRoutes           []string `flag:"api-route" cfg:"api_routes"`
	SkipAuthPreflight   bool
	SkipProviderButton  bool
	SkipJwtBearerTokens bool
	SkipAuthRegex       []string

	SignatureKey    string
	GCPHealthChecks bool

	// This is used for backwards compatibility for basic auth users
	LegacyPreferEmailToUser bool

	DefaultProvider  string
	SkipAuthRoutes   []string
	WhitelistDomains []string

	Cors CorsOptions

	ExtraJwtIssuers       []string
	SSLInsecureSkipVerify bool
	ForceJSONErrors       bool

	// internal values that are set after config validation
	redirectURL        *url.URL
	signatureData      *SignatureData
	oidcVerifier       internaloidc.IDTokenVerifier
	jwtBearerVerifiers []internaloidc.IDTokenVerifier
	realClientIPParser ipapi.RealClientIPParser
}

type CookieOptions struct {
	Name           string        `flag:"cookie-name" cfg:"cookie_name"`
	Secret         string        `json:"secret,omitempty"`
	Domains        []string      `flag:"cookie-domain" cfg:"cookie_domains"`
	Path           string        `flag:"cookie-path" cfg:"cookie_path"`
	Expire         Duration      `json:"expire,omitempty" default:"168m"`
	Refresh        Duration      `json:"refresh,omitempty"`
	Secure         bool          `flag:"cookie-secure" cfg:"cookie_secure"`
	HTTPOnly       bool          `flag:"cookie-httponly" cfg:"cookie_httponly"`
	SameSite       string        `flag:"cookie-samesite" cfg:"cookie_samesite"`
	CSRFPerRequest bool          `flag:"cookie-csrf-per-request" cfg:"cookie_csrf_per_request"`
	CSRFExpire     time.Duration `flag:"cookie-csrf-expire" cfg:"cookie_csrf_expire"`
}

type CorsOptions struct {
	Credentials    bool
	AllowedHeaders []string
	AllowedOrigins []string
}

// TLS contains the information for loading a TLS certificate and key
// as well as an optional minimal TLS version that is acceptable.
type TLS struct {
	// Key is the TLS key data to use.
	// Typically this will come from a file.
	Key *SecretSource

	// Cert is the TLS certificate data to use.
	// Typically this will come from a file.
	Cert *SecretSource

	// MinVersion is the minimal TLS version that is acceptable.
	// E.g. Set to "TLS1.3" to select TLS version 1.3
	MinVersion string

	// CipherSuites is a list of TLS cipher suites that are allowed.
	// E.g.:
	// - TLS_RSA_WITH_RC4_128_SHA
	// - TLS_RSA_WITH_AES_256_GCM_SHA384
	// If not specified, the default Go safe cipher list is used.
	// List of valid cipher suites can be found in the [crypto/tls documentation](https://pkg.go.dev/crypto/tls#pkg-constants).
	CipherSuites []string
}

// Options for Getting internal values
func (o *AlphaOptions) GetRedirectURL() *url.URL                      { return o.Server.redirectURL }
func (o *AlphaOptions) GetSignatureData() *SignatureData              { return o.Server.signatureData }
func (o *AlphaOptions) GetOIDCVerifier() internaloidc.IDTokenVerifier { return o.Server.oidcVerifier }
func (o *AlphaOptions) GetJWTBearerVerifiers() []internaloidc.IDTokenVerifier {
	return o.Server.jwtBearerVerifiers
}
func (o *AlphaOptions) GetRealClientIPParser() ipapi.RealClientIPParser {
	return o.Server.realClientIPParser
}

// Options for Setting internal values
func (o *AlphaOptions) SetRedirectURL(s *url.URL)                      { o.Server.redirectURL = s }
func (o *AlphaOptions) SetSignatureData(s *SignatureData)              { o.Server.signatureData = s }
func (o *AlphaOptions) SetOIDCVerifier(s internaloidc.IDTokenVerifier) { o.Server.oidcVerifier = s }
func (o *AlphaOptions) SetJWTBearerVerifiers(s []internaloidc.IDTokenVerifier) {
	o.Server.jwtBearerVerifiers = s
}
func (o *AlphaOptions) SetRealClientIPParser(s ipapi.RealClientIPParser) {
	o.Server.realClientIPParser = s
}
func ServerDefaults() Server {
	server := Server{
		ProxyPrefix:        "/oauth2",
		RealClientIPHeader: "X-Real-IP",
		PingPath:           "/ping",

		Logging:   loggingDefaults(),
		Session:   sessionOptionsDefaults(),
		Templates: templatesDefaults(),
		Cookie: CookieOptions{
			Name:           "_oauth2_proxy",
			Secret:         "",
			Domains:        nil,
			Path:           "/",
			Expire:         Duration(time.Duration(168) * time.Hour),
			Refresh:        Duration(time.Duration(0)),
			Secure:         true,
			HTTPOnly:       true,
			SameSite:       "",
			CSRFPerRequest: false,
			CSRFExpire:     time.Duration(15) * time.Minute,
		},
		Cors: CorsOptions{
			Credentials: false,
		},
	}

	return server
}
