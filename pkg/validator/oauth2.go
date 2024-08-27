package validator

import (
	"context"
	"github.com/MicahParks/keyfunc"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"github.com/golang-jwt/jwt/v4"
	"go.opentelemetry.io/otel"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"strings"
	"sync"
)

type OAuth2Validator struct {
	authCookieName   string
	authHeaderName   string
	claims           jwt.MapClaims
	claimsToValidate []string
	jwksServers      []*keyfunc.JWKS
	issuer           string
	log              *zap.Logger
	rawIdentityData  []byte
	requestHeaders   map[string]string
}

const (
	TokenSigningAlgorithm = "RS256"
	TokenAlgorithmClaim   = "alg"
	TokenIssuerClaim      = "iss"
)

func NewOAuth2Validator(
	authCookieName, authHeaderName, issuer string,
	claimsToValidate []string,
	jwksServers []*keyfunc.JWKS,
	requestHeaders map[string]string,
	log *zap.Logger) *OAuth2Validator {

	return &OAuth2Validator{
		authCookieName:   authCookieName,
		authHeaderName:   authHeaderName,
		claimsToValidate: claimsToValidate,
		jwksServers:      jwksServers,
		issuer:           issuer,
		log:              log,
		requestHeaders:   requestHeaders,
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
	ctx, span := otel.Tracer(tracerName).Start(ctx, "oauth2-validator")
	defer span.End()

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

			token, err := jwt.Parse(b64JwtToken, jwks.Keyfunc)
			if err != nil {
				v.log.Info("failed to parse the JWT", zap.Error(err))
				return
			}

			if token.Valid {
				if claims, ok := token.Claims.(jwt.MapClaims); ok {
					v.claims = claims
				} else {
					v.log.Error("failed to get claims from token", zap.Error(err))
					return
				}
			}

			if token.Header[TokenAlgorithmClaim] != TokenSigningAlgorithm {
				v.log.Error("token signing algorithm is wrong")
				return
			}

			if v.claims[TokenIssuerClaim].(string) != v.issuer {
				v.log.Error("issuer claim is not as expected", zap.String("claim_name", TokenIssuerClaim), zap.String("want", v.issuer), zap.String("got", v.claims[TokenIssuerClaim].(string)))
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
	var (
		email string
	)

	if e, ok := v.claims["emails"]; ok {
		email = e.([]interface{})[0].(string)
	} else {
		v.log.Info("token doesn't contain email claim")
		email = ""
	}

	identityHeaders = append(identityHeaders, &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{
			Key:   "X-Forwarded-Email",
			Value: email,
		},
		Append: wrapperspb.Bool(false),
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
