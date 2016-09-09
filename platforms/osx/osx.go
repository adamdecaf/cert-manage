package osx

import (
	"github.com/adamdecaf/cert-manage/lib"
)

type OSX struct {
	lib.Platform
}

func (o OSX) FindCerts() []lib.Cert {
	return findCerts()
}
