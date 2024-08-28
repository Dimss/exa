package authz

import (
	"context"
	"github.com/Dimss/exa/pkg/options"
	"github.com/Dimss/exa/pkg/validator"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/gogo/googleapis/google/rpc"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
)

type Service struct {
	authv3.UnimplementedAuthorizationServer
	opts *options.Options
}

func (s *Service) Check(c context.Context, request *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	// init authentication context
	authCtx := validator.NewAuthContext(request, s.opts)
	// execute validation chain
	if valid, validatedIdentity := authCtx.Valid(context.Background()); valid {
		return s.allowRequest(validatedIdentity)
	} else {
		authCtx.Log.Info("authentication context is not valid, request denied")
		return s.denyRequestWithRedirect("https://github.com")
	}
}

func (s *Service) allowRequest(identityHeaders []*corev3.HeaderValueOption) (*authv3.CheckResponse, error) {
	resp := &authv3.CheckResponse{
		Status: &status.Status{Code: int32(rpc.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: identityHeaders,
			},
		},
		DynamicMetadata: nil,
	}
	return resp, nil
}

func (s *Service) denyRequestWithRedirect(redirectUrl string) (*authv3.CheckResponse, error) {
	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(rpc.UNAUTHENTICATED)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Found},
				Headers: []*corev3.HeaderValueOption{
					{
						Header: &corev3.HeaderValue{
							Key:   "Location",
							Value: redirectUrl,
						},
					},
					{
						Header: &corev3.HeaderValue{
							Key:   "Cache-Control",
							Value: "private, max-age=0, no-store",
						},
					},
				},
			},
		},
	}, nil
}

func (s *Service) denyRequestWithHtml(httpBody string) (*authv3.CheckResponse, error) {

	return &authv3.CheckResponse{
		Status: &status.Status{Code: int32(rpc.UNAUTHENTICATED)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
				Headers: []*corev3.HeaderValueOption{
					{
						Header: &corev3.HeaderValue{
							Key:   "Content-Type",
							Value: "text/html",
						},
					},
					{
						Header: &corev3.HeaderValue{
							Key:   "Cache-Control",
							Value: "private, max-age=0, no-store",
						},
					},
				},
				Body: httpBody,
			},
		},
	}, nil
}

func NewAuthzService(grpcServer *grpc.Server, opts *options.Options) {
	svc := &Service{
		UnimplementedAuthorizationServer: authv3.UnimplementedAuthorizationServer{},
		opts:                             opts,
	}
	authv3.RegisterAuthorizationServer(grpcServer, svc)
}
