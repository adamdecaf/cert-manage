package certs

import (
	"crypto/x509"
)

// Chrome uses sqlite, so just a diff fs path for each platform?

// Reading
// http://stackoverflow.com/questions/22532870/encrypted-cookies-in-chrome

// Win
//  C:\Users\<your_username>\AppData\Local\Google\Chrome\User Data\Default\

// OSX
//  ~/Library/Application Support/Google/Chrome/Default/Cookies

// Linux
//  ~/.config/google-chrome/Default/Cookies

// Sqlite
// https://github.com/mattn/go-sqlite3

func FindCertsChrome() ([]*x509.Certificate, error) {
	return nil, nil
}
