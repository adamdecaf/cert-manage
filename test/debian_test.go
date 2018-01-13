package test

import (
	"testing"
)

func TestDebian__suite(t *testing.T) {
	t.Parallel()

	img := Dockerfile("envs/debian")
	linuxSuite(t, img, cfg{
		total:        "166",
		after:        "5",
		curlExitCode: "35",
	})
}

func TestDebian__java(t *testing.T) {
	t.Parallel()

	img := Dockerfile("envs/debian")
	javaSuite(t, img, "166", "12")
}
