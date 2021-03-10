// +build traefikfuzz

package server

import (
	"context"
	"errors"
	ptypes "github.com/traefik/paerser/types"
	"github.com/traefik/traefik/v2/pkg/config/static"
	"github.com/traefik/traefik/v2/pkg/tcp"
	"net"
	"net/http"
	"time"
)

func startEntrypoint(entryPoint *TCPEntryPoint, router *tcp.Router) (net.Conn, error) {
	go entryPoint.Start(context.Background())

	entryPoint.SwitchRouter(router)

	for i := 0; i < 10; i++ {
		conn, err := net.Dial("tcp", entryPoint.listener.Addr().String())
		if err != nil {
			continue
		}
		defer conn.Close()

		return conn, err
	}
	return nil, errors.New("entry point never started")
}

func FuzzConnWrite(data []byte) int {
	epConfig := &static.EntryPointsTransport{}
	epConfig.SetDefaults()
	epConfig.RespondingTimeouts.ReadTimeout = ptypes.Duration(2 * time.Second)

	entryPoint, err := NewTCPEntryPoint(context.Background(), &static.EntryPoint{
		Address:          ":0",
		Transport:        epConfig,
		ForwardedHeaders: &static.ForwardedHeaders{},
	})
	if err != nil {
		return -1
	}

	router := &tcp.Router{}
	router.HTTPHandler(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))

	conn, err := startEntrypoint(entryPoint, router)
	if err != nil {
		return -1
	}
	_, _ = conn.Write(data)
	return 1
}
