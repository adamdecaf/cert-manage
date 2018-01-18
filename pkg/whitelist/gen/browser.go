package gen

import (
	"fmt"
	"net/url"

	"github.com/go-sqlite/sqlite3"
)

// TODO(adam): impl
func FromAllBrowsers() ([]*url.URL, error) {
	u, err := url.Parse("http://apple.com")
	return []*url.URL{u}, err
}

// TODO(adam): impl
func FromBrowser(name string) ([]*url.URL, error) {
	db, err := sqlite3.Open("/Users/adam/Library/Application Support/Firefox/Profiles/rrdlhe7o.default/places.sqlite")
	if err != nil {
		return nil, err
	}

	err = db.VisitTableRecords("moz_places", func(rowId *int64, rec sqlite3.Record) error {
		if rowId == nil {
			return fmt.Errorf("unexpected nil RowID in Chrome sqlite database")
		}

		url, ok := rec.Values[1].(string)
		if !ok {
			fmt.Println(rec.Values)
		}
		fmt.Println(url)

		return nil
	})

	return nil, err
}
