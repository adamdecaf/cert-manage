package test

import (
	"testing"
)

func TestDebian(t *testing.T) {
	img := Dockerfile("envs/debian")
	linuxSuite(t, img, "166", "5")

	img = Dockerfile("envs/debian")
	javaSuite(t, img, "166", "12")
}
