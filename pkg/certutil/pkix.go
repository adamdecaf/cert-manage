package certutil

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"regexp"
	"strings"
)

var (
	oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}
)

// TODO(adam): Replace with RDSSquence.String() in g1.10
func StringifyPKIXName(name pkix.Name) (out string) {
	if len(name.OrganizationalUnit) > 0 {
		out = fmt.Sprintf("%s, %s", strings.Join(name.Organization, " "), name.OrganizationalUnit[0])
	}

	if out == "" {
		out = strings.Join(name.Organization, " ")
	}

	for i := range name.Names {
		if name.Names[i].Type.Equal(oidCommonName) {
			s, ok := name.Names[i].Value.(string)
			if ok {
				return cleanPKIXName(s)
			}
		}
	}

	return cleanPKIXName(out)
}

// Remove annoying characters from PKIX names
// e.g. newlines, line feeds, tabs, etc
func cleanPKIXName(name string) string {
	space := " "
	stripper := strings.NewReplacer("\n", space, "\r\n", space, "\t", space, "\r", space, "\f", space, "\v", space)
	name = stripper.Replace(name)

	trimmer := regexp.MustCompile(`(\s{1,})`)
	return trimmer.ReplaceAllString(name, " ")
}
