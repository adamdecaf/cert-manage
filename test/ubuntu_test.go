package test

import (
	"testing"
)

func TestUbuntu(t *testing.T) {
	img := Dockerfile("envs/ubuntu")
	linuxSuite(t, img, "148", "5")

	img = Dockerfile("envs/ubuntu")
	javaSuite(t, img, "148", "9")
}
