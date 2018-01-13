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
