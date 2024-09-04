package srv

import (
	"context"
	"fmt"
	"github.com/Dimss/exa/pkg/ssocentral/ui"
	limit "github.com/aviddiviner/gin-limit"
	"github.com/coreos/go-oidc"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"io/fs"
	"log"
	"net/http"
	"net/url"
)

var (
	bg    = ""
	title = ""
)

func Run(addr, bgColor, t string) {

	bg = bgColor

	title = t

	r := gin.Default()

	r.Use(limit.MaxAllowed(1))

	r.StaticFS("/public", mustFS())

	r.GET("/", centralHandler)

	r.GET("/index.html", centralHandler)

	r.GET("/dex-login", dexLogin)

	r.GET("/dex-callback", dexCallback)

	if err := r.Run(addr); err != nil {
		log.Fatal(err)
	}
}

func dexRedirectUrl() string {
	return viper.GetString("base-url") + viper.GetString("dex-redirect-suffix")
}

func dexIssuerUrl() string {
	return viper.GetString("base-url") + viper.GetString("dex-issuer-suffix")

}

func oidcSetup() (*oidc.IDTokenVerifier, oauth2.Config) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, dexIssuerUrl())

	if err != nil {
		fmt.Println(err)
	}
	oauth2Config := oauth2.Config{
		// client_id and client_secret of the client.
		ClientID:     "example-app",
		ClientSecret: "ZXhhbXBsZS1hcHAtc2VjcmV0",

		// The redirectURL.
		//RedirectURL: viper.GetString("dex-redirect-url"),
		RedirectURL: dexRedirectUrl(),

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		//
		// Other scopes, such as "groups" can be requested.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}

	return provider.Verifier(&oidc.Config{ClientID: "example-app"}), oauth2Config
}

func dexLogin(c *gin.Context) {
	_, oauth2Config := oidcSetup()
	c.Redirect(http.StatusFound, oauth2Config.AuthCodeURL("foo-bar"))
}

func dexCallback(c *gin.Context) {
	var (
		err   error
		token *oauth2.Token
	)
	verifier, oauth2Config := oidcSetup()
	code := c.Request.FormValue("code")
	token, err = oauth2Config.Exchange(context.Background(), code)
	if err != nil {
		fmt.Println(err)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		fmt.Println(err)
		return
	}

	_, err = verifier.Verify(c.Request.Context(), rawIDToken)
	if err != nil {
		fmt.Println(err)
		return
	}

	accessToken, ok := token.Extra("access_token").(string)
	if !ok {
		fmt.Println(err)
		return
	}
	c.Request.Header.Add("raw-id-token", rawIDToken)
	c.Request.Header.Add("access-token", accessToken)

	provider, err := oidc.NewProvider(context.Background(), dexIssuerUrl())

	if err != nil {
		fmt.Println(err)
	}

	idTokenVerifier := provider.Verifier(&oidc.Config{ClientID: "example-app"})
	verifiedIdToken, err := idTokenVerifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		fmt.Println(err)
	}

	c.Request.Header.Add("expiry-on-verified-id-token", verifiedIdToken.Expiry.String())
	//kubeflow-auth
	if parsedUrl, err := url.Parse(viper.GetString("base-url")); err == nil {
		c.SetCookie("kubeflow-auth", rawIDToken, 0, "/", parsedUrl.Host, false, true)
	} else {
		zap.S().Error(err)
		zap.S().Error("can't set auth cookie, error parsing base url")
	}
	c.Redirect(http.StatusFound, viper.GetString("base-url"))
}

func centralHandler(c *gin.Context) {
	c.Data(http.StatusOK, "text/html", ui.NewCentral(title, bg, c.Request.Header).Parse())
}

func indexHandler(c *gin.Context) {
	c.Redirect(http.StatusFound, viper.GetString("app-url"))
}

func mustFS() http.FileSystem {
	sub, err := fs.Sub(ui.HtmlAssets, "tmpl/assets")

	if err != nil {
		panic(err)
	}

	return http.FS(sub)
}
