package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// LoadRSAPrivateKeyFromPEM decodes a PEM block and returns an RSA private key.
func LoadRSAPrivateKeyFromPEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		key2, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, err
		}
		var ok bool
		key, ok = key2.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("PEM is not an RSA private key")
		}
	}
	return key, nil
}
