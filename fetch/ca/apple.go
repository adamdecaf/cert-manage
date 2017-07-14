package ca

import (
	"archive/tar"
	"compress/gzip"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	appleTarballCertPage = "https://opensource.apple.com/tarballs/security_certificates"
	appleLocalTarballName = "data.tar.gz"
)

// This returns the list of tarball names (so we can find the latest one)
// and returns nil if an error occurs
func getTarballNames() []string {
	resp, err := http.DefaultClient.Get(appleTarballCertPage)
	if err != nil {
		return nil
	}
	defer func() {
		if resp.Body != nil {
			resp.Body.Close()
		}
	}()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	// Pull out the tarball names and links
	// e.g. href="security_certificates-55070.30.7.tar.gz"
	r := regexp.MustCompile(`href="([\w\_\-.]+\.tar\.gz)`)
	finds := r.FindAll(b, -1)

	out := make([]string, 0)
	for i := range finds {
		s := strings.TrimPrefix(string(finds[i]), `href="`)
		out = append(out, s)
	}

	return out
}

// Sort the names in a-z order, which since they're all named basically
// 'security_certificates-[\d]+.tar.gz' the largest tarball should be the newest.
func findLatestTarball(names []string) string {
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return names[len(names)-1]
}

// Download the tarball and return abs local fs path to tarball
func downloadTarball(u string) (string, error) {
	dir, err := ioutil.TempDir("", "cert-manage-fetcher")
	if err != nil {
		return "", err
	}
	// Deleting dir and file happens wihen `cleanup` is called
	tmp := filepath.Join(dir, appleLocalTarballName)
	out, err := os.Create(tmp)
	if err != nil {
		return "", err
	}
	defer out.Close()

	// Download the file
	resp, err := http.DefaultClient.Get(u)
	if err != nil {
		return "", err
	}
	defer func() {
		if resp.Body != nil {
			resp.Body.Close()
		}
	}()

	// Gracefully copy file to temp location
	_, err = io.Copy(out, resp.Body)

	return tmp, nil
}

// Pick out which files from the tarball are cert files and
// extract those out into our tempdir
func extractTarball(p string) error {
	dir, _ := path.Split(p)
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()

	// gzip and tar
	g, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	r := tar.NewReader(g)

	// Read each file out
	for {
		hdr, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Only process files we care about
		if hdr.Typeflag == tar.TypeReg && isCertFile(hdr.Name) {
			_, name := path.Split(hdr.Name)
			f, err := os.Create(path.Join(dir, name))
			// TODO(adam): Does this cause a big slew of fd.Close() calls at the end?
			//             Instead should we `go f.Close()` after? What if err != nil
			defer f.Close()
			if err != nil {
				return nil
			}
			io.Copy(f, r)
		}
	}

	return nil
}

func isCertFile(p string) bool {
	// Grab all files in certs/* and roots/*
	// We do this a bit strangely because we parse out the tar header info and
	// split apart the path. e.g. security-certificates-16/certs/Visa.crt
	//
	// This split will turn into 'security-certificates-16/certs', 'Visa.crt'
	// of which we match on the first half if we're looking at a file in the `certs/`
	// directory.
	paths := []string{"certs/", "roots/"}
	dir, _ := path.Split(p)
	for i := range paths {
		if strings.HasSuffix(dir, paths[i]) {
			return true
		}
	}
	return false
}

// Read out all certs from the extracted files in our tempdir
func collectCerts(p string) ([]*x509.Certificate, error) {
	dir, _ := path.Split(p)

	certs := make([]*x509.Certificate, 0)
	walker := func(p string, info os.FileInfo, err error) error {
		// Ignore directories and symlinks (non-regular files)
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		// Ignore skipdirs
		if err != nil && err != filepath.SkipDir {
			return nil
		}
		// Ignore the archive
		_, name := path.Split(p)
		ignored := []string{appleLocalTarballName, ".cvsignore"}
		for i := range ignored {
			if name == ignored[i] {
				return nil
			}
		}

		// Read the cert as DER encoded
		b, err := ioutil.ReadFile(p)
		if err != nil {
			return fmt.Errorf("error reading %s -- %s", name, err.Error())
		}
		cs, err := x509.ParseCertificates(b)
		if err != nil {
			return fmt.Errorf("error parsing cert %s -- %s", name, err.Error())
		}
		// TODO(adam): Only uniq insertions, tree/heap structure would be better
		certs = append(certs, cs...)
		return nil
	}

	err := filepath.Walk(dir, walker)
	return certs, err
}

// Cleanup the parent dir for a given path
func cleanup(p string) error {
	return os.RemoveAll(filepath.Dir(p))
}

// Pull the latest set of certs from Apple's page and
// extract them.
func Apple() ([]*x509.Certificate, error) {
	latest := findLatestTarball(getTarballNames())
	u := appleTarballCertPage + "/" + latest
	p, err := downloadTarball(u)
	if err != nil {
		return nil, err
	}
	defer cleanup(p)

	err = extractTarball(p)
	if err != nil {
		return nil, err
	}

	return collectCerts(p)
}
