package options

// AlphaOptions contains alpha structured configuration options.
// Usage of these options allows users to access alpha features that are not
// available as part of the primary configuration structure for OAuth2 Proxy.
//
// :::warning
// The options within this structure are considered alpha.
// They may change between releases without notice.
// :::
type AlphaOptions struct {
	// UpstreamConfig is used to configure upstream servers.
	// Once a user is authenticated, requests to the server will be proxied to
	// these upstream servers based on the path mappings defined in this list.
	UpstreamConfig UpstreamConfig `json:"upstreamConfig,omitempty,squash"`

	// InjectRequestHeaders is used to configure headers that should be added
	// to requests to upstream servers.
	// Headers may source values from either the authenticated user's session
	// or from a static secret value.
	InjectRequestHeaders []Header `json:"injectRequestHeaders,omitempty"`

	// InjectResponseHeaders is used to configure headers that should be added
	// to responses from the proxy.
	// This is typically used when using the proxy as an external authentication
	// provider in conjunction with another proxy such as NGINX and its
	// auth_request module.
	// Headers may source values from either the authenticated user's session
	// or from a static secret value.
	InjectResponseHeaders []Header `json:"injectResponseHeaders,omitempty"`

	// Server is used to configure the HTTP(S) server for the proxy application.
	// You may choose to run both HTTP and HTTPS servers simultaneously.
	// This can be done by setting the BindAddress and the SecureBindAddress simultaneously.
	// To use the secure server you must configure a TLS certificate and key.
	Server Server `json:"server,omitempty"`

	// MetricsServer is used to configure the HTTP(S) server for metrics.
	// You may choose to run both HTTP and HTTPS servers simultaneously.
	// This can be done by setting the BindAddress and the SecureBindAddress simultaneously.
	// To use the secure server you must configure a TLS certificate and key.
	MetricsServer Server `json:"metricsServer,omitempty"`

	// Providers are used to configure multiple providers.
	Providers Providers `json:"providers,omitempty"`

	Matching []Matching `json:"matching,omitempty"`
}

// ExtractFrom populates the fields in the AlphaOptions with the values from
// the Options
func (a *AlphaOptions) ExtractFrom(opts *Options) {
	a.UpstreamConfig = opts.UpstreamServers
	a.InjectRequestHeaders = opts.InjectRequestHeaders
	a.InjectResponseHeaders = opts.InjectResponseHeaders
	a.Server = opts.Server
	a.Server.Cookie = opts.Cookie.ToNewFormat()
	a.MetricsServer = opts.MetricsServer
	a.Providers = opts.Providers
	a.extractServerAttributesFrom(opts)
}

// extractServerAttributesFrom moves all the attributes from the old options to the new place under the Server struct
func (a *AlphaOptions) extractServerAttributesFrom(opts *Options) {
	a.Server.ProxyPrefix = opts.ProxyPrefix
	a.Server.PingPath = opts.PingPath
	a.Server.PingUserAgent = opts.PingUserAgent
	a.Server.ReverseProxy = opts.ReverseProxy
	a.Server.RealClientIPHeader = opts.RealClientIPHeader
	a.Server.TrustedIPs = opts.TrustedIPs
	a.Server.ForceHTTPS = opts.ForceHTTPS
	a.Server.RawRedirectURL = opts.RawRedirectURL
	a.Server.AuthenticatedEmailsFile = opts.AuthenticatedEmailsFile
	a.Server.EmailDomains = opts.EmailDomains
	a.Server.WhitelistDomains = opts.WhitelistDomains
	a.Server.HtpasswdFile = opts.HtpasswdFile
	a.Server.HtpasswdUserGroups = opts.HtpasswdUserGroups

	a.Server.APIRoutes = opts.APIRoutes
	a.Server.SkipAuthRegex = opts.SkipAuthRegex
	a.Server.SkipAuthRoutes = opts.SkipAuthRoutes
	a.Server.SkipJwtBearerTokens = opts.SkipJwtBearerTokens
	a.Server.ExtraJwtIssuers = opts.ExtraJwtIssuers
	a.Server.SkipProviderButton = opts.SkipProviderButton
	a.Server.SSLInsecureSkipVerify = opts.SSLInsecureSkipVerify
	a.Server.SkipAuthPreflight = opts.SkipAuthPreflight
	a.Server.ForceJSONErrors = opts.ForceJSONErrors
	a.Server.SignatureKey = opts.SignatureKey
	a.Server.GCPHealthChecks = opts.GCPHealthChecks
	a.Server.LegacyPreferEmailToUser = opts.LegacyPreferEmailToUser
	a.Server.redirectURL = opts.redirectURL
	a.Server.signatureData = opts.signatureData
	a.Server.oidcVerifier = opts.oidcVerifier
	a.Server.realClientIPParser = opts.realClientIPParser
	a.Server.jwtBearerVerifiers = opts.jwtBearerVerifiers

}

func NewAlphaOptions() *AlphaOptions {
	return &AlphaOptions{
		Server:    ServerDefaults(),
		Providers: providerDefaults(),
	}
}
