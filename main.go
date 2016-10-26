package main

import (
	"flag"
	"fmt"
	"github.com/adamdecaf/cert-manage/cmd"
	"os"
	"path/filepath"
	"strings"
)

var (
	// actions
	find = flag.Bool("find", false, "Find certs for application or platform.")
	whitelist = flag.String("whitelist", "", "Deactivate all certs except for those in the given whitelist")
	version = flag.Bool("version", false, "Output the version number")

	// where?
	app = flag.String("app", "", "Find certs for an application (optional)")
)

const Version = "0.0.1-dev"

func main() {
	flag.Parse()

	if version != nil && *version {
		fmt.Println(Version)
		return
	}

	// determine action
	if find != nil && *find {
		cmd.Find(app)
		return
	}
	if whitelist != nil && *whitelist != "" {
		w, err := filepath.Abs(strings.TrimSpace(*whitelist))
		if err != nil {
			fmt.Printf("Error finding whitelist path '%v'\n", whitelist)
			return
		}
		if validWhitelistPath(w) {
			cmd.Whitelist(w, app)
		}
		return
	}

	fmt.Println("Run `cert-manage -h` to get help information")
}

// validWhitelistPath verifies that the given whitelist filepath is properly defined
// and exists on the given filesystem.
func validWhitelistPath(path string) bool {
	valid := true
	isFlag := strings.HasPrefix(path, "-")

	if len(path) == 0 || isFlag {
		valid = false
		fmt.Printf("The given whitelist file path '%s' doesn't look correct.\n", path)
		if isFlag {
			fmt.Println("The path looks like a cli flag, -whitelist requires a path to the whitelist file.")
		} else {
			fmt.Println("The given whitelist file path is empty.")
		}
	}

	_, err := os.Stat(path)
	if err != nil {
		valid = false
		fmt.Printf("The path %s doesn't seem to exist.\n", path)
	}

	return valid
}
