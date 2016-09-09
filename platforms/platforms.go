package platforms

import (
	"fmt"
	"github.com/adamdecaf/cert-manage/lib"
	"github.com/adamdecaf/cert-manage/platforms/osx" // todo: build tags instead
	"runtime"
)

func Find() (lib.Platform, error) {
	if runtime.GOOS == "darwin" {
		p := osx.OSX{}
		return p, nil
	}

	return nil, fmt.Errorf("Unable to find platform")
}
