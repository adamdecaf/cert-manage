package ui

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"fmt"
	"html/template"
	"io"
	"net/http"

	"github.com/adamdecaf/cert-manage/tools/_x509"
	"github.com/adamdecaf/cert-manage/ui/server"
)

const (
	head = `
<!doctype html>
<html>
  <head>
    <title>cert-mange {{.Operation}}</title>
  </head>
  <body>
`
	footer = `
<script>
function toggle(sel) {
  var elm = document.querySelector("#" + sel)
  if (elm.style.display == "none") {
    elm.style.display = "block";
  } else {
    elm.style.display = "none";
  }
}
</script>
</body></html>`

	list = `
<h3>Certificates</h3>
{{range $idx, $cert := .Certificates}}
Subject: {{ $cert.Subject }}<br />
<a href="#" onclick="toggle('cert{{ $idx }}'); return false;" style="color: #000;">Details</a><br />
<span class="certificate" id="cert{{ $idx }}" style="display:none;"><pre>{{ $cert.Raw }}</pre></span><br />
{{else}}
<strong>No certificates</strong>
{{end}}
`
)

func launch() (err error) {
	server.Register()
	server.Start()
	defer func() {
		err2 := server.Stop()
		if err == nil {
			err = err2
		}
	}()
	err = Open()
	return err
}

func write(w io.Writer, tpl string, data interface{}) error {
	t, err := template.New("contents").Parse(tpl)
	if err != nil {
		io.WriteString(w, fmt.Sprintf("ERROR: %v", err))
		return err
	}
	err = t.Execute(w, data)
	if err != nil {
		io.WriteString(w, fmt.Sprintf("ERROR: %v", err))
		return err
	}
	return nil
}

func showCertsOnWeb(certs []*x509.Certificate, cfg *Config) error {
	server.Register()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p, ok := getPrinter(cfg.Format)
		if !ok {
			io.WriteString(w, fmt.Sprintf("Unknown format %s", cfg.Format))
			return
		}
		defer p.close()

		err := write(w, head, struct {
			Operation string
		}{
			Operation: "list certificates",
		})
		if err != nil {
			return
		}

		type cert struct {
			Subject string
			Raw     string
		}
		contents := make([]cert, len(certs))
		for i := range certs {
			var buf bytes.Buffer
			w1 := bufio.NewWriter(&buf)

			p.write(w1, certs[i:i+1])
			w1.Flush()

			contents[i] = cert{
				Subject: _x509.StringifyPKIXName(certs[i].Subject),
				Raw:     buf.String(),
			}
		}
		err = write(w, list, struct {
			Certificates []cert
		}{
			Certificates: contents,
		})

		write(w, footer, nil)
	})

	return launch()
}
