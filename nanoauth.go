package nanoauth


import (
	"net/http"
	"crypto/tls"
)

type handler struct {
	child http.Handler
	token string
}

// Implement the http.Handler interface. Also let clients know when I have 
// no matching route listeners
func (self handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Header.Get("X-NANOBOX-TOKEN") != self.token {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}
	req.Header.Del("X-NANOBOX-TOKEN")

	self.child.ServeHTTP(rw, req)
}

func ListenAndServeTLS(addr, token string, h http.Handler) error {
	cert, err := Generate()
	if err != nil {
		return err
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}
	config.BuildNameToCertificate()
	tlsListener, err := tls.Listen("tcp", addr, config)
	if err != nil {
		return err
	}

	return http.Serve(tlsListener, handler{child: h, token: token})
}
