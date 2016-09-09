package main

import (
	"fmt"
	"github.com/adamdecaf/cert-manage/platforms"
)

func main() {
	platform, err := platforms.Find()
	if err != nil  {
		fmt.Printf("Error finding platform - %s\n", err)
		return
	}

	certs := platform.FindCerts()
	fmt.Println(certs)
}
