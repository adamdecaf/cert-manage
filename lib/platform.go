package lib

import (
	"crypto/x509"
)

type Platform interface {
	FindCerts() []*x509.Certificate
}
