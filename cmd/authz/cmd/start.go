package cmd

import (
	"fmt"
	"github.com/Dimss/exa/pkg/authz"
	"github.com/Dimss/exa/pkg/options"
	"github.com/Dimss/exa/pkg/validator"
	grpcprometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"syscall"
)

func init() {
	startCmd.PersistentFlags().StringP("bind-addr", "b", "0.0.0.0:50052", "bind to authz server")
	startCmd.PersistentFlags().StringP("auth-cookie", "c", "_auth", "oauth cookie name")
	startCmd.PersistentFlags().StringP("auth-header", "", "authorization", "authentication header name")
	startCmd.PersistentFlags().BoolP("insecure-skip-verify", "s", true, "enable=true|disable=false https verification")
	startCmd.PersistentFlags().StringP("metrics-addr", "m", "0.0.0.0:2113", "metrics listen address")
	startCmd.PersistentFlags().StringSlice("jwks-servers", []string{}, "list of jwks server")
	startCmd.PersistentFlags().StringP("oauth2-token-issuer", "", "", "issuer of oauth2 token as it appears in iss claim")
	startCmd.PersistentFlags().StringSlice("disable-validators", []string{}, fmt.Sprintf("validator types to disable - %s|%s",
		validator.OAuthProxyType,
		validator.OAuth2Type))

	viper.BindPFlag("bind-addr", startCmd.PersistentFlags().Lookup("bind-addr"))
	viper.BindPFlag("auth-cookie", startCmd.PersistentFlags().Lookup("auth-cookie"))
	viper.BindPFlag("auth-header", startCmd.PersistentFlags().Lookup("auth-header"))
	viper.BindPFlag("insecure-skip-verify", startCmd.PersistentFlags().Lookup("insecure-skip-verify"))
	viper.BindPFlag("ingress-type", startCmd.PersistentFlags().Lookup("ingress-type"))
	viper.BindPFlag("metrics-addr", startCmd.PersistentFlags().Lookup("metrics-addr"))
	viper.BindPFlag("tracing-enabled", startCmd.PersistentFlags().Lookup("tracing-enabled"))
	viper.BindPFlag("jaeger-url", startCmd.PersistentFlags().Lookup("jaeger-url"))
	viper.BindPFlag("jwks-servers", startCmd.PersistentFlags().Lookup("jwks-servers"))
	viper.BindPFlag("oauth2-token-issuer", startCmd.PersistentFlags().Lookup("oauth2-token-issuer"))
	viper.BindPFlag("oauth2-claims-validate", startCmd.PersistentFlags().Lookup("oauth2-claims-validate"))
	viper.BindPFlag("disable-validators", startCmd.PersistentFlags().Lookup("disable-validators"))

	rootCmd.AddCommand(startCmd)
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "start exa authz server",
	Run: func(cmd *cobra.Command, args []string) {
		mux := http.NewServeMux()
		mux.HandleFunc("/profile", pprof.Profile)
		go func() { http.ListenAndServe(":7777", mux) }()

		startServer()
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

func startServer() {
	var grpcServer *grpc.Server

	metricsInterceptor := authz.GrpcMetrics.UnaryServerInterceptor()

	lis, err := net.Listen("tcp", viper.GetString("bind-addr"))
	if err != nil {
		zap.S().Fatalf("failed to listen: %v", err)
	}

	grpcServerOption := grpc.UnaryInterceptor(metricsInterceptor)

	grpcServer = grpc.NewServer(grpcServerOption)
	grpcprometheus.Register(grpcServer)
	authz.NewAuthzService(
		grpcServer,
		options.NewOptionsFromFlags(),
	)
	// Initialize all metrics.
	authz.GrpcMetrics.InitializeMetrics(grpcServer)
	authz.GrpcMetrics.EnableHandlingTimeHistogram()
	startMetrics()

	zap.S().Infof("grpc control plane server listening on %s", viper.GetString("bind-addr"))
	if err := grpcServer.Serve(lis); err != nil {
		zap.S().Fatal(err)
	}
}

func startMetrics() {
	addr := viper.GetString("metrics-addr")
	http.Handle("/metrics", promhttp.HandlerFor(authz.Reg, promhttp.HandlerOpts{}))
	go func() {
		zap.S().Infof("Prometheus metrics bind address %s", viper.GetString("metrics-addr"))
		err := http.ListenAndServe(addr, nil)
		if err != nil {
			zap.S().Error("failed to start metrics server: ", err)
			return
		}
	}()
}
