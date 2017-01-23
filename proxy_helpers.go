// https://git.io/goproxy

package main

import (
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/golibs/lrucache"
	"github.com/phuslu/glog"
)

type FlushWriter struct {
	w io.Writer
}

func (fw FlushWriter) Write(p []byte) (n int, err error) {
	n, err = fw.w.Write(p)
	if f, ok := fw.w.(http.Flusher); ok {
		f.Flush()
	}
	return
}

type TCPListener struct {
	*net.TCPListener
}

func (ln TCPListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	tc.SetReadBuffer(32 * 1024)
	tc.SetWriteBuffer(32 * 1024)
	return tc, nil
}

type SimplePAM struct {
	CacheSize uint

	path  string
	cache lrucache.Cache
	once  sync.Once
}

func (p *SimplePAM) init() {
	p.cache = lrucache.NewLRUCache(p.CacheSize)

	exe, err := os.Executable()
	if err != nil {
		glog.Fatalf("Ensure bundled `pwauth' error: %+v", err)
	}

	p.path = filepath.Join(filepath.Dir(exe), "pwauth")
	if _, err := os.Stat(p.path); err != nil {
		glog.Fatalf("Ensure bundled `pwauth' error: %+v", err)
	}

	switch runtime.GOOS {
	case "linux", "freebsd", "darwin":
		if u, err := user.Current(); err == nil && u.Uid == "0" {
			glog.Warningf("If you want to use system native pwauth, please run as root, otherwise please add/edit pwauth.txt.")
		}
	case "windows":
		glog.Warningf("Current platform %+v not support native pwauth, please add/edit pwauth.txt.", runtime.GOOS)
	}
}

func (p *SimplePAM) Authenticate(username, password string) error {
	auth := username + ":" + password

	if _, ok := p.cache.GetNotStale(auth); ok {
		return nil
	}

	cmd := exec.Command(p.path)
	cmd.Stdin = strings.NewReader(username + "\n" + password + "\n")
	err := cmd.Run()

	if err != nil {
		glog.Warningf("SimplePAM: username=%v password=%v error: %+v", username, password, err)
		time.Sleep(time.Duration(5+rand.Intn(6)) * time.Second)
		return err
	}

	p.cache.Set(auth, struct{}{}, time.Now().Add(2*time.Hour))
	return nil
}
