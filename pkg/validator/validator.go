package validator

import (
	"context"
	"github.com/Dimss/exa/pkg/options"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"regexp"
	"sync"
)

const (
	OAuthProxyType = "oauthproxy"
	OAuth2Type     = "oauth2"
)

var (
	SkipRoutePaths = []string{ // TODO(dimss): make this parameter
		"/centralsso/dex-login",
		"/dex-login",
		"/dex/*",
	}
)

type validator interface {
	isValid(context.Context) bool
	ValidatedIdentity() (identityHeaders []*corev3.HeaderValueOption)
}

type AuthContext struct {
	opts    *options.Options
	request *authv3.CheckRequest
	Log     *zap.Logger
}

func (ac *AuthContext) Valid(ctx context.Context) (bool, []*corev3.HeaderValueOption) {

	var validators []validator

	if ac.skipAuthRoute() {
		return true, nil
	}

	if ac.opts.OAuth2ValidatorEnabled() {
		validators = append(validators, NewOAuth2Validator(
			ac.opts,
			ac.request.Attributes.Request.Http.Headers,
			ac.Log,
		))
	}

	type IdentityHeaders []*corev3.HeaderValueOption
	var wg sync.WaitGroup

	type ValidationRes struct {
		valid   bool
		headers IdentityHeaders
	}

	resCh := make(chan ValidationRes)
	defer close(resCh)

	for _, val := range validators {
		wg.Add(1)
		v := val
		go func() {
			defer wg.Done()
			if v.isValid(ctx) {
				ac.Log.Info("authentication context is valid, request allowed")
				resCh <- ValidationRes{
					valid:   true,
					headers: v.ValidatedIdentity(),
				}
			}
		}()
	}

	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		wg.Wait()
		doneCh <- struct{}{}

	}()

	for {
		select {
		case result := <-resCh:
			return result.valid, result.headers
		case <-doneCh:
			return false, nil
		}
	}
}

func (ac *AuthContext) skipAuthRoute() bool {
	for _, skipPath := range SkipRoutePaths {
		// TODO (dimssss) load regex at load time, make the part of options struct
		skipPathRegex, err := regexp.Compile(skipPath)
		if err != nil {
			ac.Log.Error(err.Error(), []zap.Field{
				{
					Key:    "skipPath",
					Type:   zapcore.StringType,
					String: skipPath,
				}}...)
			continue
		}
		if skipPathRegex.Match([]byte(ac.request.Attributes.Request.Http.Path)) {
			return true
		}
	}
	return false
}

func NewAuthContext(r *authv3.CheckRequest, opts *options.Options) *AuthContext {

	return &AuthContext{
		request: r,
		opts:    opts,
		Log: zap.L().With(
			[]zap.Field{
				{
					Key:    "host",
					Type:   zapcore.StringType,
					String: r.Attributes.Request.Http.Host,
				},
				{
					Key:    "path",
					Type:   zapcore.StringType,
					String: r.Attributes.Request.Http.Path,
				},
				{
					Key:    "schema",
					Type:   zapcore.StringType,
					String: r.Attributes.Request.Http.Scheme,
				},
				{
					Key:    "rid",
					Type:   zapcore.StringType,
					String: r.Attributes.Request.Http.Headers["x-request-id"],
				},
			}...,
		),
	}
}
