[![Build Status](https://travis-ci.org/nanobox-io/golang-nanoauth.svg)](https://travis-ci.org/nanobox-io/golang-nanoauth)
[![GoDoc](https://godoc.org/github.com/nanobox-io/golang-nanoauth?status.svg)](https://godoc.org/github.com/nanobox-io/golang-nanoauth)

# golang-nanoauth

Nanoauth provides a uniform means of serving HTTP/S for golang projects securely. It allows the specification of a certificate (or generates one) as well as an auth token which is checked before the request is processed.


## Quickstart

Import and serve
>main.go
>```go
package main

import (
	"net/http"
	"fmt"
	"io"

	"github.com/nanobox-io/golang-nanoauth"
)

func main() {
  http.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
    io.WriteString(rw, "World, Hello!\n")
  })

	fmt.Printf("Stopped serving! - %v\n",
		nanoauth.ListenAndServe("127.0.0.1:8081", "$ECRET", nil))
}
```
Test
```sh
$ curl localhost:8081 -i
# HTTP/1.1 401 Unauthorized
# Date: Thu, 09 Jun 2016 22:18:55 GMT
# Content-Length: 0
# Content-Type: text/plain; charset=utf-8

$ curl -H 'X-NANOBOX-TOKEN: $ECRET' localhost:8081 -i
# HTTP/1.1 200 OK
# Date: Thu, 09 Jun 2016 22:27:24 GMT
# Content-Length: 14
# Content-Type: text/plain; charset=utf-8
# 
# World, hello!
```


## Usage

Generate a cert and customize auth the token header
```go
...
	cert, _ := nanoauth.Generate("logvac.nanopack.io")
	auth := nanoauth.Auth{
		Header:      "X-AUTH-TOKEN",
		Certificate: cert,
	}
	return auth.ListenAndServeTLS(config.ListenHttp, "secret", router, "/")
...
```


## Contributing

Contributions to the nanobox-router project are welcome and encouraged. Contributions should follow the [Nanobox Contribution Process & Guidelines](https://docs.nanobox.io/contributing/).


## Licence

Mozilla Public License Version 2.0


[![open source](http://nano-assets.gopagoda.io/open-src/nanobox-open-src.png)](http://nanobox.io/open-source)
