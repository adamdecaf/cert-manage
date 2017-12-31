package server

import (
	"fmt"
	"io"
	"net/http"
	"sync"
)

var (
	srv *http.Server
	wg  sync.WaitGroup
)

// Address returns the http://$server:$port/ representation for clients to load
func Address() string {
	if srv == nil {
		return ""
	}
	return fmt.Sprintf("http://%s/", srv.Addr)
}

func Register() {
	if srv != nil {
		return // already initialized
	}

	srv = &http.Server{
		// TODO(adam): Can we pick a random port?
		Addr: "127.0.0.1:8888",
	}

	// http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	// 	io.WriteString(w, "hello world\n")
	// })
	http.HandleFunc("/done", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "finished\n")
		wg.Done()
	})
}

// Start initializes the http server, binds and accepts connections
func Start() {
	if srv == nil {
		// TODO(adam): should we log here?
		return
	}

	wg.Add(1) // force callers to wait

	// spawn off http server
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			fmt.Printf("ERROR: failed creating localhost server err=%s\n", err)
		}
	}()
}

// Stop calls for a shutdown of the http server, if it exists
func Stop() error {
	// hold on until the form has been filled out
	wg.Wait()

	if srv != nil {
		return srv.Shutdown(nil)
	}
	return nil
}
