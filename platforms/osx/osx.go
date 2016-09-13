package osx

import (
	"crypto/x509"
	"github.com/adamdecaf/cert-manage/lib"
)

type OSX struct {
	lib.Platform
}

func (o OSX) FindCerts() []*x509.Certificate {
	return findCerts()
}
