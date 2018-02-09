package test

import (
	"testing"
)

func TestUbuntu__suite(t *testing.T) {
	t.Parallel()
	curlExitCode := "35"

	img := Dockerfile("envs/ubuntu")
	linuxSuite(t, img, cfg{
		total:        "148",
		after:        "5",
		curlExitCode: curlExitCode,
	})
	opensslSuite(t, img, cfg{
		total:        "", // TODO(adam): find openssl counts
		after:        "",
		curlExitCode: curlExitCode,
	})
}

func TestUbuntu__java(t *testing.T) {
	t.Parallel()

	img := Dockerfile("envs/ubuntu")
	javaSuite(t, img, "148", "9")
}
