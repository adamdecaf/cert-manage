package test

import (
	"testing"
)

func TestAlpine(t *testing.T) {
	// os specific tests (and values), will change on each release
	img := Dockerfile("envs/alpine")
	linuxSuite(t, img, "151", "5")

	// App specific tests
	img = Dockerfile("envs/alpine")
	javaSuite(t, img, "150", "") // TODO(adam): `after` param
}
