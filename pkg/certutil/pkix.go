package certutil

import (
	"crypto/x509/pkix"
	"fmt"
	"strings"
)

// TODO(adam): Replace with RDSSquence.String() in g1.10
func StringifyPKIXName(name pkix.Name) string {
	if len(name.OrganizationalUnit) > 0 {
		return fmt.Sprintf("%s, %s", strings.Join(name.Organization, " "), name.OrganizationalUnit[0])
	}
	return strings.Join(name.Organization, " ")
}
