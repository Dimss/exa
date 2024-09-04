package cmd

import (
	"github.com/Dimss/exa/pkg/ssocentral/srv"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"os"
	"os/signal"
	"syscall"
)

func init() {
	startCmd.PersistentFlags().StringP(
		"bind-addr",
		"a",
		"0.0.0.0:8080",
		"bind to authz server")
	startCmd.PersistentFlags().StringP(
		"base-url",
		"",
		"http://127.0.0.1",
		"base url")
	startCmd.PersistentFlags().StringP(
		"dex-issuer-suffix",
		"",
		":5556/dex",
		"dex issuer url")
	startCmd.PersistentFlags().StringP(
		"dex-redirect-suffix",
		"",
		":8080/dex-callback",
		"dex callback url")

	viper.BindPFlag("bind-addr", startCmd.PersistentFlags().Lookup("bind-addr"))
	viper.BindPFlag("dex-issuer-suffix", startCmd.PersistentFlags().Lookup("dex-issuer-suffix"))
	viper.BindPFlag("dex-redirect-suffix", startCmd.PersistentFlags().Lookup("dex-redirect-suffix"))
	viper.BindPFlag("base-url", startCmd.PersistentFlags().Lookup("base-url"))

	rootCmd.AddCommand(startCmd)
}

var startCmd = &cobra.Command{
	Use:     "start",
	Short:   "start sso central server",
	Aliases: []string{"central"},
	Run: func(cmd *cobra.Command, args []string) {
		srv.Run(viper.GetString("bind-addr"), "white", "SSO CENTRAL")
		// handle interrupts
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		for {
			select {
			case s := <-sigCh:
				zap.S().Infof("signal: %s, shutting down", s)
				zap.S().Info("bye bye 👋")
				os.Exit(0)
			}
		}
	},
}
