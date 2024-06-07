package pkg

import (
	"context"
	"net/http"
	"time"

	"connectrpc.com/connect"

	"github.com/uinta-labs/iotnetlab/gen/protos/connections/firm/ware/dev"
	"github.com/uinta-labs/iotnetlab/gen/protos/connections/firm/ware/dev/devconnect"
)

type ConnectivityServer struct{}

func NewConnectivityServer() *ConnectivityServer {
	return &ConnectivityServer{}
}

var _ devconnect.ConnectivityServiceHandler = (*ConnectivityServer)(nil)

func (s *ConnectivityServer) InternetConnectivityCheck(baseCtx context.Context, c *connect.Request[dev.InternetConnectivityCheckRequest]) (*connect.Response[dev.InternetConnectivityCheckResponse], error) {
	timeoutMs := c.Msg.GetTimeoutMillis()
	if timeoutMs == 0 {
		timeoutMs = 5000
	}

	ctx, cancel := context.WithTimeout(baseCtx, time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()

	targetURL := "https://www.google.com/generate_204"

	httpClient := &http.Client{
		Timeout: time.Duration(timeoutMs) * time.Millisecond,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return &connect.Response[dev.InternetConnectivityCheckResponse]{
			Msg: &dev.InternetConnectivityCheckResponse{
				IsConnected: false,
			},
		}, nil
	}

	return &connect.Response[dev.InternetConnectivityCheckResponse]{
		Msg: &dev.InternetConnectivityCheckResponse{
			IsConnected: true,
		},
	}, nil
}
