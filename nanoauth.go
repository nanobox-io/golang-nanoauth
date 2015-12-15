package nanoauth

import (
	"crypto/tls"
	"net/http"
)

type Auth struct {
	child         http.Handler
	Header        string
	Certificate   *tls.Certificate
	ExcludedPaths []string
	Token         string
}

var DefaultAuth = &Auth{}

func init() {
	DefaultAuth.Header = "X-NANOBOX-TOKEN"
	DefaultAuth.Certificate, _ = Generate("nanobox.io")
}

// Implement the http.Handler interface. Also let clients know when I have
// no matching route listeners
func (self Auth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	reqPath := req.URL.Path
	check := true
	for _, path := range self.ExcludedPaths {
		if path == reqPath {
			check = false
			break
		}
	}

	if check && req.Header.Get(self.Header) != self.Token {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	self.child.ServeHTTP(rw, req)
}

func (self *Auth) ListenAndServeTLS(addr, token string, h http.Handler, excludedPaths ...string) error {
	config := &tls.Config{
		Certificates: []tls.Certificate{*self.Certificate},
	}
	config.BuildNameToCertificate()
	tlsListener, err := tls.Listen("tcp", addr, config)
	if err != nil {
		return err
	}
	self.ExcludedPaths = excludedPaths
	self.Token = token
	self.child = h

	return http.Serve(tlsListener, self)
}

// ListenAndServeTLS quick function to get to the default one
func ListenAndServeTLS(addr, token string, h http.Handler, excludedPaths ...string) error {
	return DefaultAuth.ListenAndServeTLS(addr, token, h, excludedPaths...)
}
