package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/grpcreflect"
	"github.com/caarlos0/env/v10"
	"github.com/godbus/dbus/v5"
	"github.com/pkg/errors"
	"github.com/rs/cors"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/uinta-labs/iotnetlab/gen/protos/connections/firm/ware/dev"
	"github.com/uinta-labs/iotnetlab/gen/protos/connections/firm/ware/dev/devconnect"
	"github.com/uinta-labs/iotnetlab/internal"
)

//func pamAuth(serviceName, username string) error {
//	transaction, err := pam.StartFunc(serviceName, username, func(s pam.Style, msg string) (string, error) {
//		if s == pam.PromptEchoOff || s == pam.PromptEchoOn {
//			var response string
//			fmt.Printf("%s: ", msg)
//			fmt.Scanln(&response)
//			return response, nil
//		}
//		return "", fmt.Errorf("unrecognized PAM message style")
//	})
//	if err != nil {
//		return err
//	}
//
//	if err := transaction.Authenticate(0); err != nil {
//		return err
//	}
//
//	return nil
//}
//
//func ensurePermissions(ctx context.Context) error {
//	euid := os.Geteuid()
//	if euid != 0 {
//		log.Printf("Not running as root (EUID=%d), attempting to authenticate with PAM\n", euid)
//
//		err := pamAuth(os.Args[0], "root")
//		if err != nil {
//			return errors.Wrap(err, "failed to authenticate with PAM")
//		}
//
//		// now check if we are root
//		if _, err := exec.CommandContext(ctx, "id", "-u").Output(); err != nil {
//			return errors.New("failed to authenticate as root")
//		}
//	}
//	log.Println("Running with an effective UID of 0")
//
//	return nil
//}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(startTime))
	})
}

// WiFiNetwork represents a single WiFi network.
type WiFiNetwork struct {
	SSID      string `json:"ssid"`
	Frequency uint32 `json:"frequency"`
	Strength  uint8  `json:"strength"`
	Security  string `json:"security"`
}

type wifiServer struct {
	dbusConn *dbus.Conn
}

func (w wifiServer) Scan(ctx context.Context, c *connect.Request[dev.WiFiScanRequest]) (*connect.Response[dev.WiFiScanResponse], error) {
	var maxScanTimeSeconds int = 0
	if c.Msg.MaxTimeSeconds > 0 {
		maxScanTimeSeconds = int(c.Msg.MaxTimeSeconds)
	}
	if maxScanTimeSeconds > 60 {
		return nil, errors.New("Scan MaxTimeSeconds is capped at 60 seconds")
	}
	scanCtx, cancelScanCtx := context.WithTimeout(ctx, time.Second*time.Duration(maxScanTimeSeconds))
	defer cancelScanCtx()

	accessPoints, err := internal.WifiScan(scanCtx, w.dbusConn, "")
	if err != nil {
		return nil, err
	}

	return &connect.Response[dev.WiFiScanResponse]{
		Msg: &dev.WiFiScanResponse{
			ScanResult: &dev.WiFiScanResult{
				AccessPoints: accessPoints,
			},
		},
	}, nil

}

func (w wifiServer) Connect(ctx context.Context, c *connect.Request[dev.WiFiConnectRequest]) (*connect.Response[dev.WiFiConnectResponse], error) {
	connectionCtx, cancelConnectionCtx := context.WithTimeout(ctx, time.Minute)
	defer cancelConnectionCtx()

	err := internal.ConnectWiFi(connectionCtx, w.dbusConn, c.Msg)
	if err != nil {
		return nil, err
	}

	return &connect.Response[dev.WiFiConnectResponse]{
		Msg: &dev.WiFiConnectResponse{
			//🤷
			Success: true,
		},
	}, nil
}

func (w wifiServer) Disconnect(ctx context.Context, c *connect.Request[dev.WiFiDisconnectRequest]) (*connect.Response[dev.WiFiDisconnectResponse], error) {
	//TODO implement me
	panic("implement me")
}

func (w wifiServer) GetStatus(ctx context.Context, c *connect.Request[dev.WiFiGetStatusRequest]) (*connect.Response[dev.WiFiGetStatusResponse], error) {
	//TODO implement me
	panic("implement me")
}

var _ devconnect.WiFiServiceHandler = (*wifiServer)(nil)

type Config struct {
	Debug bool   `env:"DEBUG" envDefault:"false"`
	Host  string `env:"HOST" envDefault:"0.0.0.0"`
	Port  string `env:"PORT" envDefault:"5600"`
}

func ReadConfig() (Config, error) {
	cfg := Config{}
	parseErr := env.Parse(&cfg)
	if parseErr != nil {
		return cfg, errors.Wrap(parseErr, "failed to parse environment variables")
	}

	return cfg, nil
}

var (
	hotspotSSID      = flag.String("hotspot-ssid", "", "SSID of the hotspot")
	hotspotPass      = flag.String("hotspot-pass", "", "Password of the hotspot")
	hotspotInterface = flag.String("hotspot-interface", "", "Interface to use for the hotspot (e.g. wlan0)")

	modeScan      = flag.Bool("scan", false, "Scan for WiFi networks")
	scanInterface = flag.String("scan-interface", "", "Interface to use for scanning (e.g. wlan0)")
)

func main() {
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn, err := dbus.SystemBus()
	if err != nil {
		log.Fatalf("Failed to connect to System Bus: %v", err)
	}
	defer conn.Close()

	if *hotspotSSID != "" && *hotspotPass != "" {
		err := internal.StartHotspot(ctx, conn, *hotspotSSID, *hotspotPass, *hotspotInterface)
		if err != nil {
			log.Fatalf("Failed to start hotspot: %v", err)
		}
	}

	if *modeScan {
		accessPoints, err := internal.WifiScan(ctx, conn, *scanInterface)
		if err != nil {
			log.Fatalf("Failed to scan for WiFi networks: %v", err)
		}

		for _, ap := range accessPoints {
			log.Printf("SSID: %s, Frequency: %d, Strength: %d, Security: %s, Channel: %d\n", ap.SSID, ap.Frequency, ap.GetRSSI(), ap.SecurityType.String(), ap.GetChannel())
		}
	}

	srv := &wifiServer{
		dbusConn: conn,
	}

	httpMux := http.NewServeMux()

	reflector := grpcreflect.NewStaticReflector(
		"connections.firm.ware.dev.WiFiService",
		"connections.firm.ware.dev.TimeService",
	)
	httpMux.Handle(grpcreflect.NewHandlerV1(reflector))
	httpMux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))

	{
		baseURL, connectHandler := devconnect.NewWiFiServiceHandler(srv)
		log.Printf("Binding WiFiService to %s\n", baseURL)
		httpMux.Handle(baseURL, connectHandler)
	}

	{
		timeSrv := internal.NewTimeServer(conn)
		baseURL, connectHandler := devconnect.NewTimeServiceHandler(timeSrv)
		log.Printf("Binding TimeService to %s\n", baseURL)
		httpMux.Handle(baseURL, connectHandler)
	}

	cfg, err := ReadConfig()
	if err != nil {
		log.Fatalf("failed to read config: %+v\n", err)
	}

	corsConfig := cors.New(cors.Options{
		AllowOriginFunc: func(origin string) bool {
			return true
		},
		AllowedOrigins: []string{
			//"http://localhost:3000",
		},
		AllowedMethods: []string{
			"GET",
			"PATCH",
			"POST",
			"OPTIONS",
		},
		AllowCredentials: true,
		AllowedHeaders: []string{
			"Authorization",
			"Baggage",
			"Connect-Protocol-Version",
			"Content-Type",
			"Cookie",
			"Origin",
			"Sentry-Trace",
			"User-Agent",
			"Baggage",
			"Sentry-Trace",
		},
		Debug: cfg.Debug,
	})

	withLogging := loggingMiddleware(httpMux)
	withCors := corsConfig.Handler(withLogging)
	httpServer := http.Server{
		Addr:              cfg.Host + ":" + cfg.Port,
		Handler:           h2c.NewHandler(withCors, &http2.Server{}),
		ReadTimeout:       time.Second * 30,
		WriteTimeout:      time.Second * 30,
		IdleTimeout:       time.Second * 60,
		ReadHeaderTimeout: time.Second * 10,
		ErrorLog:          log.New(os.Stderr, "HTTP Server: ", log.LstdFlags),
	}

	go func() {
		log.Println("Starting server on", httpServer.Addr)
		err := httpServer.ListenAndServe()
		if err != nil {
			log.Println("Server error:", err)
		}
	}()

	<-ctx.Done()

	log.Println("Shutting down server...")
	if err := httpServer.Shutdown(ctx); err != nil {
		log.Println("Server shutdown error:", err)
	}
}
