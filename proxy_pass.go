// https://git.io/goproxy

package main

import (
	"net/http"
)

type PassHandler struct {
	*http.Transport
}

func (h *PassHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	return
}
