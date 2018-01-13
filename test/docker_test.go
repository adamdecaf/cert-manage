package test

import (
	"testing"
)

func TestDocker_basic(t *testing.T) {
	img := Dockerfile("envs/basic")
	img.Run("date", "-u")
	img.SuccessT(t)
}

func TestDocker_hasSuffix(t *testing.T) {
	img := Dockerfile("envs/basic/Dockerfile")
	img.Run("date", "-u")
	img.SuccessT(t)
}

func TestDocker_shouldFail(t *testing.T) {
	img := Dockerfile("envs/basic")
	img.ShouldFail("nothing")
	img.SuccessT(t)

	img = Dockerfile("envs/basic")
	img.ShouldFail("nothing", "other")
	img.SuccessT(t)
}

func TestDocker__exitCode(t *testing.T) {
	img := Dockerfile("envs/basic")
	img.ExitCode("0", "date")
	img.ExitCode("127", "asjdsfjsafkjas")
	img.SuccessT(t)
}
