package validator

import (
	"context"
	"github.com/Dimss/exa/pkg/options"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"net/http"
	"sync"
)

const tracerName = "validator"

type validator interface {
	isValid(context.Context) bool
	ValidatedIdentity() (identityHeaders []*corev3.HeaderValueOption)
}

const (
	OAuthProxyType = "oauthproxy"
	OAuth2Type     = "oauth2"
)

type AuthContext struct {
	opts    *options.Options
	request *authv3.CheckRequest
	Log     *zap.Logger
}

func (ac *AuthContext) Valid(ctx context.Context) (bool, []*corev3.HeaderValueOption) {
	span := trace.SpanFromContext(ctx)

	if ac.request.Attributes.Request.Http.Method == http.MethodOptions {
		span.AddEvent("skipping auth, method is OPTIONS")
		return true, nil
	}

	var validators []validator

	if ac.opts.OAuth2ValidatorEnabled() {
		validators = append(validators, NewOAuth2Validator(
			ac.opts.AuthCookie,
			ac.opts.AuthHeader,
			ac.opts.Oauth2TokenIssuer,
			ac.opts.Oauth2ClaimsValidate,
			ac.opts.JwksServers,
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
