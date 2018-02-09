package test

import (
	"testing"
)

func TestAlpine__suite(t *testing.T) {
	t.Parallel()
	curlExitCode := "60"

	img := Dockerfile("envs/alpine")
	linuxSuite(t, img, cfg{
		total:        "151",
		after:        "5",
		curlExitCode: curlExitCode,
	})
	opensslSuite(t, img, cfg{
		total:        "", // TODO(adam): find openssl counts
		after:        "",
		curlExitCode: curlExitCode,
	})
}

func TestAlpine__java(t *testing.T) {
	t.Parallel()

	img := Dockerfile("envs/alpine")
	javaSuite(t, img, "150", "5")
}
