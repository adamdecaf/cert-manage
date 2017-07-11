package _tls

import (
	"crypto/tls"
)

// Why isn't this obtainable from the stdlib?
func Ver2String(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLSv1"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	default:
		return "unknown"
	}
}
