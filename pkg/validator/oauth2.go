package validator

import (
	"context"
	"github.com/MicahParks/keyfunc"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/golang-jwt/jwt/v4"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"strings"
	"sync"
)

type OAuth2Validator struct {
	authCookieName  string
	authHeaderName  string
	jwksServers     []*keyfunc.JWKS
	log             *zap.Logger
	claims          jwt.MapClaims
	rawIdentityData []byte
	requestHeaders  map[string]string
}

func NewOAuth2Validator(
	authCookieName string,
	authHeaderName string,
	jwksServers []*keyfunc.JWKS,
	requestHeaders map[string]string,
	log *zap.Logger) *OAuth2Validator {

	return &OAuth2Validator{
		authCookieName: authCookieName,
		authHeaderName: authHeaderName,
		jwksServers:    jwksServers,
		log:            log,
		requestHeaders: requestHeaders,
		claims:         jwt.MapClaims{},
	}
}

func (v *OAuth2Validator) shouldValidate() bool {
	if _, ok := v.requestHeaders[v.authHeaderName]; ok {
		return true
	}
	if len(v.getAuthCookie()) > 0 {
		return true
	}
	return false
}

func (v *OAuth2Validator) isValid(ctx context.Context) bool {

	if !v.shouldValidate() {
		v.log.Info("not OAuth2 based authentication, aborting")
		return false
	}

	var wg sync.WaitGroup
	successValidationCh := make(chan bool)
	defer close(successValidationCh)
	b64JwtToken := v.jwtToken()

	// Validate JWT on each JWKS in parallel
	for _, jwks := range v.jwksServers {
		wg.Add(1)
		go func(jwks *keyfunc.JWKS) {

			defer wg.Done()

			token, err := jwt.ParseWithClaims(b64JwtToken, v.claims, jwks.Keyfunc)
			if err != nil {
				v.log.Info("not valid token", zap.Error(err))
				return
			}

			if !token.Valid {
				v.log.Error("failed to get claims from token", zap.Error(err))
				return

			}

			successValidationCh <- true

		}(jwks)
	}

	failedValidationCh := make(chan struct{})

	go func() {
		defer close(failedValidationCh)
		wg.Wait()
		failedValidationCh <- struct{}{}
	}()

	for {
		select {
		case <-successValidationCh:
			return true
		case <-failedValidationCh:
			return false
		}
	}
}

func (v *OAuth2Validator) ValidatedIdentity() (identityHeaders []*corev3.HeaderValueOption) {

	email := ""
	if e, ok := v.claims["email"]; ok {
		email = e.(interface{}).(string)
	} else {
		v.log.Info("token doesn't contain email claim")
	}

	identityHeaders = append(identityHeaders, &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{
			Key:   v.authHeaderName,
			Value: email,
		},
	})

	identityHeaders = append(identityHeaders, &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{
			Key:   "foo-bar-xyz",
			Value: "HELLO WORLD",
		},
	})

	return
}

func (v *OAuth2Validator) jwtToken() string {
	if authCookieValue := v.getAuthCookie(); len(authCookieValue) > 0 {
		v.log = v.log.With(zap.Field{Key: "authType", Type: zapcore.StringType, String: "cookie"})
		token := strings.Split(authCookieValue, "=")
		if len(token) < 1 {
			v.log.Error("wrong cookie format")
			return ""
		}
		return token[1]
	}
	return strings.TrimSpace(strings.ReplaceAll(v.requestHeaders[v.authHeaderName], "Bearer", ""))

}

func (v *OAuth2Validator) getAuthCookie() string {
	for _, cookie := range strings.Split(v.requestHeaders["cookie"], ";") {
		if strings.Contains(cookie, v.authCookieName) {
			return cookie
		}
	}
	return ""
}
