package nanoauth_test

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/nanobox-io/golang-nanoauth"
)

func ExampleListenAndServe() {
	http.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		io.WriteString(rw, "World, Hello!\n")
	})

	nanoauth.ListenAndServe("127.0.0.1:80", "secret", nil)
}

func ExampleListenAndServeTLS() {
	http.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		io.WriteString(rw, "World, Hello!\n")
	})

	cert, _ := nanoauth.Generate("nanoauth.nanopack.io")
	nanoauth.DefaultAuth.Header = "X-AUTH-TOKEN"
	nanoauth.DefaultAuth.Certificate = cert

	nanoauth.ListenAndServeTLS("127.0.0.1:443", "secret", nil)
}

// TestMain initializes the environment and runs the tests
func TestMain(m *testing.M) {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	// create default route
	http.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		io.WriteString(rw, "World, Hello!\n")
	})

	rtn := m.Run()

	os.Exit(rtn)
}

// TestListenServe tests ListenAndServe functionality
func TestListenServe(t *testing.T) {
	address1 := "127.0.0.1:8081"

	go nanoauth.ListenAndServe(address1, "$ECRET", nil)
	time.Sleep(time.Second)

	// test good request
	req, err := newReq(address1, "/")
	if err != nil {
		t.Errorf("Failed to create request - %v", err)
		t.FailNow()
	}
	req.Header.Add("X-NANOBOX-TOKEN", "$ECRET")
	req.Host = "nanobox-router.test"

	resp, err := getIt(req)
	if err != nil {
		t.Errorf("Failed to create request - %v", err)
		t.FailNow()
	}

	if resp != "World, Hello!\n" {
		t.Errorf("%q doesn't match expected out", resp)
	}

	// test bad request
	req, err = newReq(address1, "/")
	if err != nil {
		t.Errorf("Failed to create request - %v", err)
		t.FailNow()
	}
	req.Header.Add("X-NANOBOX-TOKEN", "PUBLIC")
	req.Host = "nanobox-router.test"

	resp, err = getIt(req)
	if err != nil {
		t.Errorf("Failed to create request - %v", err)
		t.FailNow()
	}

	if resp == "World, Hello!\n" {
		t.Errorf("%q doesn't match expected out", resp)
	}
}

// TestListenServeTLS tests ListenAndServeTLS functionality
func TestListenServeTLS(t *testing.T) {
	address2 := "127.0.0.1:8082"

	go nanoauth.ListenAndServeTLS(address2, "$ECRET", nil)
	time.Sleep(time.Second)

	// test good request
	req, err := newReqS(address2, "/")
	if err != nil {
		t.Errorf("Failed to create request - %v", err)
		t.FailNow()
	}
	req.Header.Add("X-NANOBOX-TOKEN", "$ECRET")
	req.Host = "nanobox-router.test"

	resp, err := getIt(req)
	if err != nil {
		t.Errorf("Failed to create request - %v", err)
		t.FailNow()
	}

	if resp != "World, Hello!\n" {
		t.Errorf("%q doesn't match expected out", resp)
	}

	// test bad request
	req, err = newReqS(address2, "/")
	if err != nil {
		t.Errorf("Failed to create request - %v", err)
		t.FailNow()
	}
	req.Header.Add("X-NANOBOX-TOKEN", "PUBLIC")
	req.Host = "nanobox-router.test"

	resp, err = getIt(req)
	if err != nil {
		t.Errorf("Failed to create request - %v", err)
		t.FailNow()
	}

	if resp == "World, Hello!\n" {
		t.Errorf("%q doesn't match expected out", resp)
	}
}

// TestLoad tests loading cert/key from file functionality
func TestLoad(t *testing.T) {
	err := writeKeyPair()
	if err != nil {
		t.Errorf("Failed to write key/cert - %v", err)
		t.FailNow()
	}

	_, err = nanoauth.Load("/tmp/pub.crt", "/tmp/priv.key", "")
	if err != nil {
		t.Errorf("Failed to load key/cert - %v", err)
	}

	// test failed loading
	_, err = nanoauth.Load("/tmp/no-way-hose", "/tmp/priv.key", "")
	if err == nil {
		t.Errorf("Failed to fail loading key/cert - %v", err)
	}
	_, err = nanoauth.Load("/tmp/pub.crt", "/tmp/no-way-a", "")
	if err == nil {
		t.Errorf("Failed to fail loading key/cert - %v", err)
	}
}

// write key pair to files
func writeKeyPair() error {
	// self-signed keypair generated locally
	pub := `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAO8vbJ40g9igMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTYwNjA5MjMwNzAzWhcNMTcwNjA5MjMwNzAzWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA0Uz1OJQ1vUmNfR6oDTcYsAcEIvWJLJ0+VCo67DMgpt2E/vLqKa6Ljb08
HZphAwMVVg3NF3dWNmgAxJS6KPF8I4gpeDQ1WdnjP9Q1r6WJlkE+SG6kWKuiMJUh
2jFRntb5/mzxLhds9g8JdQXRJeb5oolok0BJ/JGlc338tokL9czF4dTBL1kHdqZB
D4wP4evEotln30y4Wfp2wlvvR5jSuuvg/n/mxhtmt8PEEL2D5QKx6zwJdR0osccc
XJFRwAuAg19Xw5C9JZ4r+ilRghKzow8Db6d3Wyard+h9UZawns18X+ZWfj9q+3/T
bS9V39JD3LV/iOp2LXAr50TmN4QNTQIDAQABo1AwTjAdBgNVHQ4EFgQUC3h9qDf/
4msiNT+Nx31gNj/Sl+UwHwYDVR0jBBgwFoAUC3h9qDf/4msiNT+Nx31gNj/Sl+Uw
DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAXrJ5GW36UVDkWK2Uv7qb
SODdMj2WUxxbb724AKSizTYV75MepPfp6HCipbilfmPDWXnFd14ecgSI4+dfyP5L
rXhNk+kkmklyqR+c8YuG+ALoS77vsfBr24fLUPNpLjCwph5CNTce1UH0yw/ReT2L
xYWe45KtIjHIBU1jv4CKG8Cpi+Mj3wveREOEFQ6OxdxvtrgjhbEI1NDiqlnW5dFi
VHfPOt0KnoJx0rX0oP0Mp+6Qwt2orvMeqGjguAhGKyN6w5SrdJQ5PuRP+906W67w
Bz6qeOT9g4i9Na6x3/UmVArW8bUwnGn4Ll+551IrVxOynuLeaCTLbAFYt9/6NcRp
Yg==
-----END CERTIFICATE-----
`
	priv := `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA0Uz1OJQ1vUmNfR6oDTcYsAcEIvWJLJ0+VCo67DMgpt2E/vLq
Ka6Ljb08HZphAwMVVg3NF3dWNmgAxJS6KPF8I4gpeDQ1WdnjP9Q1r6WJlkE+SG6k
WKuiMJUh2jFRntb5/mzxLhds9g8JdQXRJeb5oolok0BJ/JGlc338tokL9czF4dTB
L1kHdqZBD4wP4evEotln30y4Wfp2wlvvR5jSuuvg/n/mxhtmt8PEEL2D5QKx6zwJ
dR0oscccXJFRwAuAg19Xw5C9JZ4r+ilRghKzow8Db6d3Wyard+h9UZawns18X+ZW
fj9q+3/TbS9V39JD3LV/iOp2LXAr50TmN4QNTQIDAQABAoIBAFd/usyqeUTm6PWz
yUGtFO8SH9KVn4E9Q39gID36qd3Yoe8LkoVWaRUaVXVywrfFpDfTkTgMNciM9jU4
kBLp0aHxHJUaDmu/wVc/2inSJJDiOa2CQ8amCioRTpOvJpYm/WA2HyXLuUuswaFg
iy0zQI2IsGVO7R9frDF6LBoLdSqObWAp0tQyUGMueVSozNBdED1kzAbl9GCb/LnB
Z7VVOwoX/cFagbK8fO60QEIwCQcx9lHyshdAVs4gJO0vG3Uo/qsFE+X/zPQQLnBk
2NwSEasL1RNxTzkkBuuZY7cpPlKl1wvbrRFukqTF/l5xYlhqkgKdBY+NbJYJW7RC
T8aIwykCgYEA6+GcZlFnOi0rAumc/Ykoe9B5egh71Rok7ZrF8zBV32E5VyEmO7Gc
qsaATBYOH/+h9TzH0yOhPaJ7kqxaijh9IrkRwABvkl0to4B6jvqDk41H/oRnUcbN
fWyxdnCnEwSGSJsTYid7jWY7Y4+M5nNjH2YZ96Wv5nJWbTtGaSzD6cMCgYEA4yb3
gAR8dSlZfQVhCG51zOtecIFDyQHAODPrHHzzOeuxdMD/ty2NoZT5QGrOri+dMhO/
1xGRnSWxSAuiBV0rLLxFavVO7IR7Mu/xnK3ELnuSp9yrtK8icZCyY7G9uY9mhnuG
YhSKO4zG+iYugmSrl63psvAwTPvyWp9hQGSmq68CgYAhc3dIk1a+S1WELjkTQ3Y4
SNJRWg6lo/WEtKRJ3pru+My27H6NjJyZI1licOZD527CZoI4ER92rCo2HLciTuyA
FhrMTcOE0C3+t+OpjyFFtY12LLSyRi0yEk4Aa+1lpwicF1HiY5MD9HGLpvnmXIq8
EzCvjBGr7p8PEo7jr3OBHQKBgCIb6tRVWB77u41TbnOmqpe/zCmWr4gSdDu8SBS6
CofrBXWjuYJXG8pkpVzv7OMpETDA2HDCGZyAWXOZE5Y8nEwWZVIfTd+kMR+/+gbt
7OSR976vGzWBiumEsdTYjsW7a8jL6az2qp8wj3xmmVtJJJ8dJVeSS55zwruq7R6P
PpvPAoGALyrSqIvzsxO/6m9vafjYrQ3u0TeJSsAVqJKSs47paeJIJeT1p6rotoJn
HRdLurBXAy38LKU7wK5aS8aE2NOhpxzRHl1jjW0I3lgf8H7oGM4U48FPme/VSOZA
fpowwqaBTnIoKBbR0i5L1NXagsaZBqJX8blzWZg7aq8D8wz7L/w=
-----END RSA PRIVATE KEY-----
`

	pubBytes := []byte(pub)
	err := ioutil.WriteFile("/tmp/pub.crt", pubBytes, 0644)
	if err != nil {
		return err
	}

	privBytes := []byte(priv)
	err = ioutil.WriteFile("/tmp/priv.key", privBytes, 0600)
	if err != nil {
		return err
	}

	return nil
}

func newReq(address, path string) (*http.Request, error) {
	req, err := http.NewRequest("GET", "http://"+address+path, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to create Request - %v", err)
	}
	return req, nil
}

func newReqS(address, path string) (*http.Request, error) {
	req, err := http.NewRequest("GET", "https://"+address+path, nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to create Request - %v", err)
	}
	return req, nil
}

func getIt(req *http.Request) (string, error) {
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Failed test GET - %v", err)
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("Failed to read Body - %v", err)
	}

	return string(b), nil
}
