package osx

import (
	"bufio"
	"bytes"
	"encoding/pem"
	"fmt"
	"github.com/adamdecaf/cert-manage/lib"
	"io"
	"os/exec"
)

const (
	PEMHeader = "-----BEGIN CERTIFICATE-----"
	PEMFooter = "-----END CERTIFICATE-----"
	PEMDash = 0x2d
	PEMLine = 0x0a
)

// import encoding/pem
// shell out: 'security find-certificate -a -p'
//  then parse ^

func findCerts() []lib.Cert {
	bodies, err := getPEMCertBodiesFromCLI()
	if err != nil {
		return nil
	}

	// var certs []lib.Cert
	for i := range bodies {
		block, rest := pem.Decode(bodies[i]) // todo: read bytes from exec.Cmd
		if block != nil {
			fmt.Println("block")
			fmt.Printf("  type: %s\n", block.Type)
			fmt.Printf("  headers: %v\n", block.Headers)
			fmt.Printf("  rest = %s\n\n", string(rest))
		}
	}

	return nil
}

func peekForDash(r bufio.Reader) (bool, error) {
	b, err := r.Peek(1)
	if err != nil {
		return false, err
	}
	if len(b) > 0 {
		return b[0] == PEMDash, nil
	}
	return false, nil
}

func readHeaderOrFooter(r bufio.Reader) error {
	cond, err := peekForDash(r)
	if err != nil {
		return nil
	}
	if cond {
		return readAndSkipLine(r)
	}
	return nil
}

func readAndSkipLine(r bufio.Reader) error {
	_, err := r.ReadBytes(PEMLine)
	return err
}

func getPEMCertBodiesFromCLI() ([][]byte, error) {
	b, err := exec.Command("security", "find-certificate", "-a", "-p").Output()
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(b)
	buf := bufio.NewReader(r)
	if buf == nil {
		return nil, fmt.Errorf("error creating buffered reader")
	}

	var bodies [][]byte
	for {
		err = readHeaderOrFooter(*buf)
		if err == io.EOF {
			break
		}

		fmt.Println("D")
		body, err := readPEMCertBody(*buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		bodies = append(bodies, body)
		err = readHeaderOrFooter(*buf)
		if err != nil {
			return nil, err
		}
	}

	return bodies, nil
}

func readPEMCertBody(r bufio.Reader) ([]byte, error) {
	var body []byte
	for {
		fmt.Println("A")
		cond, err := peekForDash(r)
		if err != nil {
			return nil, nil
		}
		// if the line starts with '-', break
		if cond {
			fmt.Println("B")
			readAndSkipLine(r)
			break
		}
		fmt.Println("C")

		// otherwise, read line
		line, err := r.ReadBytes(PEMLine)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		for i := range line {
			fmt.Println("E")
			body = append(body, line[i])
		}
		fmt.Println("F")
	}
	return body, nil
}
