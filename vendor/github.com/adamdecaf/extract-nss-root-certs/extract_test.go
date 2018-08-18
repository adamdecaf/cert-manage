package nsscerts

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"
)

var (
	expectedCertCount = 132

	isTravis = os.Getenv("TRAVIS_OS_NAME") != ""
	isCron = os.Getenv("TRAVIS_EVENT_TYPE") == "cron"

	maxDownloadSize = int64(10 * 1024 * 1024)
)

func TestExtractNSS(t *testing.T) {
	bs, err := ioutil.ReadFile("testdata/certdata.txt")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{}
	r := bytes.NewReader(bs)
	certs, err := List(r, cfg)
	if err != nil {
		t.Fatal(err)
	}

	if len(certs) != expectedCertCount {
		t.Errorf("got %d certs, expected %d", len(certs), expectedCertCount)
	}
}

// https://docs.travis-ci.com/user/cron-jobs/#Detecting-Builds-Triggered-by-Cron
func TestExtractNSS_weekly(t *testing.T) {
	if !isTravis || !isCron {
		t.Skip("not in travisci cron")
	}

	client := http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Get(LatestDownloadURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if resp.Body != nil {
			resp.Body.Close()
		}
	}()
	r := io.LimitReader(resp.Body, maxDownloadSize)

	// parse
	certs, err := List(r, &Config{})
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != expectedCertCount {
		t.Errorf("got %d certs, expected %d", len(certs), expectedCertCount)
	}
}
