// https://git.io/goproxy

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/cloudflare/golibs/lrucache"
	"github.com/phuslu/glog"
	"github.com/phuslu/goproxy/httpproxy/helpers"
	"github.com/phuslu/net/http2"
	"golang.org/x/crypto/acme/autocert"
)

var (
	version = "r9999"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

type Config struct {
	Default struct {
		LogLevel int `toml:"log_level"`
	}
	Server []struct {
		Enabled    bool     `toml:"enabled"`
		Listen     []string `toml:"listen"`
		ServerName string   `toml:"server_name"`

		ProxyMode       string   `toml:"proxy_mode"`
		ProxyFallback   string   `toml:"proxy_fallback"`
		ProxyPass       string   `toml:"proxy_pass"`
		ProxyAuthHeader bool     `toml:"proxy_auth_header"`
		ProxyAuthMethod string   `toml:"proxy_auth_method"`
		ProxyAuthArgs   []string `toml:"proxy_auth_args"`
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-version" {
		fmt.Print(version)
		return
	}

	var config Config

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "os.Executable() error: %+v\n", err)
		os.Exit(1)
	}

	tomlData, err := ioutil.ReadFile(exe + ".toml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ioutil.ReadFile(%s.toml) error: %+v\n", exe, err)
		os.Exit(1)
	}

	_, err = toml.Decode(string(tomlData), &config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "toml.Decode(%s) error: %+v\n", tomlData, err)
		os.Exit(1)
	}

	helpers.SetFlagsIfAbsent(map[string]string{
		"logtostderr": "true",
		"v":           strconv.Itoa(config.Default.LogLevel),
	})
	flag.Parse()

	dialer := &helpers.Dialer{
		Dialer: &net.Dialer{
			KeepAlive: 0,
			Timeout:   16 * time.Second,
			DualStack: true,
		},
		Resolver: &helpers.Resolver{
			LRUCache:  lrucache.NewLRUCache(8 * 1024),
			BlackList: lrucache.NewLRUCache(1024),
			DNSExpiry: 8 * time.Hour,
		},
	}

	if ips, err := helpers.LocalIPv4s(); err == nil {
		for _, ip := range ips {
			dialer.Resolver.BlackList.Set(ip.String(), struct{}{}, time.Time{})
		}
		for _, s := range []string{"127.0.0.1", "::1"} {
			dialer.Resolver.BlackList.Set(s, struct{}{}, time.Time{})
		}
	}

	transport := &http.Transport{
		Dial: dialer.Dial,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ClientSessionCache: tls.NewLRUClientSessionCache(1024),
		},
		TLSHandshakeTimeout: 16 * time.Second,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     180,
		DisableCompression:  false,
	}

	servername := config.Server[0].ServerName

	handler := &LocalHandler{
		ServerName: servername,
		Transport:  transport,
	}

	domains := []string{}
	for _, server := range config.Server {
		domains = append(domains, server.ServerName)
	}

	m := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache("."),
		HostPolicy: autocert.HostWhitelist(domains...),
	}

	srv := &http.Server{
		Handler: handler,
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: m.GetCertificate,
		},
	}

	http2.ConfigureServer(srv, &http2.Server{})

	for _, server := range config.Server {
		addr := server.Listen[0]
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			glog.Fatalf("Listen(%s) error: %s", addr, err)
		}
		glog.Infof("goproxy-vps %s ListenAndServe on %s\n", version, ln.Addr().String())
		go srv.Serve(tls.NewListener(TCPListener{ln.(*net.TCPListener)}, srv.TLSConfig))
	}

	select {}
}
