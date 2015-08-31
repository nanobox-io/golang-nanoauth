package nanoauth

import (
  "crypto/tls"
  "crypto/rand"
  "crypto/rsa"
  "crypto/x509"
  "crypto/x509/pkix"
  "encoding/pem"
  "math/big"
  "time"
)

func Generate() (*tls.Certificate, error) {
  host := "gonano.io"

  priv, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    return nil, err
  }

  notBefore := time.Now()

  notAfter := notBefore.Add(365*24*100*time.Hour) // 100 years..


  serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
  serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
  if err != nil {
    return nil, err
  }

  template := x509.Certificate{
    SerialNumber: serialNumber,
    Subject: pkix.Name{
      Organization: []string{"Acme Co"},
    },
    NotBefore: notBefore,
    NotAfter:  notAfter,

    KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
    ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
    BasicConstraintsValid: true,
  }

  template.DNSNames = append(template.DNSNames, host)

  derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
  if err != nil {
    return nil, err
  }

  cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
  key := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
  c, err := tls.X509KeyPair(cert, key)
  return &c, err
}