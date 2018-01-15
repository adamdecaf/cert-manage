package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/adamdecaf/cert-manage/pkg/whitelist/gen"
)

func GenerateWhitelist(from, file string) error {
	if from == "" && file == "" {
		return errors.New("you need to specify either -from or -file")
	}
	choices := getChoices(from, file)
	for i := range choices {
		opt := strings.ToLower(strings.TrimSpace(choices[i]))
		switch opt {
		case "browser", "browsers":
			urls, err := gen.FromAllBrowsers()
			if err != nil {
				return err
			}
			fmt.Printf("urls=%d\n", len(urls))
		case "chrome", "edge", "firefox", "ie", "opera", "safari":
			urls, err := gen.FromBrowser(opt)
			if err != nil {
				return err
			}
			fmt.Printf("urls=%d\n", len(urls))
		case "file":
			urls, err := gen.FromFile(file)
			if err != nil {
				return err
			}
			fmt.Printf("urls=%q\n", urls)
		}
	}

	return nil
}

func getChoices(from, file string) []string {
	if !strings.Contains(from, "file") && file != "" {
		if from != "" {
			from += ",file"
		}
		from += "file"
	}
	return strings.Split(from, ",")
}
