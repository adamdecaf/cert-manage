package lib

type Platform interface {
	FindCerts() []Cert
}
