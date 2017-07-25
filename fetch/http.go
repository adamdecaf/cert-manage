package fetch

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
)

// Process over an array of urls and return their raw bytes.
// TODO(adam): Switch to not reading the entire body inmem
func getRawDataFromUrls(urls []string) [][]byte {
	mu := sync.Mutex{}
	out := make([][]byte, 0)

	wait := sync.WaitGroup{}
	wait.Add(len(urls))

	for _,u := range urls {
		go func(url string)  {
			mu.Lock()
			defer mu.Unlock()
			defer wait.Done()

			b := httpGetToBytes(url)
			if len(b) > 0 {
				out = append(out, b)
			}
		}(u)
	}

	wait.Wait()
	return out
}

// HTTP GET the data and read it off into a byte array
func httpGetToBytes(url string) []byte {
	resp, err := http.Get(url)
	if err != nil {
		return nil
	}
	defer func() {
		e := resp.Body.Close()
		if e != nil {
			fmt.Printf("error closing http GET - %s\n", e)
		}
	}()

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	return b
}
