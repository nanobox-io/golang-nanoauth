package nanoauth

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

// Load is a helper function to load a certificate and key from password protected files.
func Load(certFile, keyFile, password string) (*tls.Certificate, error) {
	certPEMBlock, err := ioutil.ReadFile(certFile)
	if err != nil {
		return &tls.Certificate{}, err
	}
	keyPEMBlock, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return &tls.Certificate{}, err
	}
	temp, _ := pem.Decode(keyPEMBlock)
	if x509.IsEncryptedPEMBlock(temp) {
		keyPEMBlock, err = x509.DecryptPEMBlock(temp, []byte(password))
		if err != nil {
			return &tls.Certificate{}, err
		}
	}
	crt, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	return &crt, err
}
