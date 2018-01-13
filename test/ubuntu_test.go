package test

import (
	"testing"
)

func TestUbuntu__suite(t *testing.T) {
	img := Dockerfile("envs/ubuntu")
	linuxSuite(t, img, cfg{
		total:        "148",
		after:        "5",
		curlExitCode: "35",
	})
}

func TestUbuntu__java(t *testing.T) {
	img := Dockerfile("envs/ubuntu")
	javaSuite(t, img, "148", "9")
}
