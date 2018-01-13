package test

import (
	"testing"
)

func TestAlpine__suite(t *testing.T) {
	t.Parallel()

	img := Dockerfile("envs/alpine")
	linuxSuite(t, img, cfg{
		total:        "151",
		after:        "5",
		curlExitCode: "60",
	})
}

func TestAlpine__java(t *testing.T) {
	t.Parallel()

	img := Dockerfile("envs/alpine")
	javaSuite(t, img, "150", "5")
}
