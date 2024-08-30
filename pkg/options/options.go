package options

import (
	"context"
	"crypto/tls"
	"github.com/MicahParks/keyfunc"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"net/http"
	"time"
)

const (
	OAuthProxyType = "oauthproxy"
	OAuth2Type     = "oauth2"
)

type Options struct {
	AuthCookie           string
	AuthTokenSrcHeader   string
	UserIdHeader         string
	InsecureSkipVerify   bool
	JwksServerURLs       []string
	Oauth2TokenIssuer    string
	Oauth2ClaimsValidate []string
	DisableValidators    []string
	RedirectUrl          string
	JwksServers          []*keyfunc.JWKS
}

func NewOptionsFromFlags() *Options {
	opts := &Options{
		AuthCookie:           viper.GetString("auth-cookie"),
		AuthTokenSrcHeader:   viper.GetString("token-src-header"),
		UserIdHeader:         viper.GetString("user-id-header"),
		InsecureSkipVerify:   viper.GetBool("insecure-skip-verify"),
		JwksServerURLs:       viper.GetStringSlice("jwks-servers"),
		Oauth2ClaimsValidate: viper.GetStringSlice("oauth2-claims-validate"),
		Oauth2TokenIssuer:    viper.GetString("oauth2-token-issuer"),
		RedirectUrl:          viper.GetString("redirect-url"),
		DisableValidators:    viper.GetStringSlice("disable-validators"),
	}

	if opts.OAuth2ValidatorEnabled() {
		opts.initJwksKeyfuncs()
	}

	return opts
}

func (opts *Options) validatorDisabled(validatorType string) bool {
	for _, d := range opts.DisableValidators {
		if d == validatorType {
			return true
		}
	}
	return false
}

func (opts *Options) OAuthProxyValidatorEnabled() bool {
	return !opts.validatorDisabled(OAuthProxyType)
}

func (opts *Options) OAuth2ValidatorEnabled() bool {
	return !opts.validatorDisabled(OAuth2Type)
}

func (opts *Options) initJwksKeyfuncs() {

	transCfg := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ToDo(dimssss):  this shouldn't be here
	}

	client := &http.Client{Transport: transCfg}
	// Create the keyfunc options. Use an error handler that logs. Refresh the JWKS when a JWT signed by an unknown KID
	// is found or at the specified interval. Rate limit these refreshes. Timeout the initial JWKS refresh request after
	// 10 seconds. This timeout is also used to create the initial context.Context for keyfunc.Get.
	options := keyfunc.Options{
		Ctx: context.Background(),
		RefreshErrorHandler: func(err error) {
			zap.S().Error(err)
		},
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
		Client:            client,
	}

	for _, u := range opts.JwksServerURLs {
		zap.S().Infof("adding jwks server: %s", u)
		// Create the JWKS from the resource at the given URL.
		jwks, err := keyfunc.Get(u, options)
		if err != nil {
			zap.S().Error(err)
		}
		opts.JwksServers = append(opts.JwksServers, jwks)
	}
}
