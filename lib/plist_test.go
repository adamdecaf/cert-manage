package lib

import (
	"fmt"
	// "io/ioutil"
	// "github.com/DHowett/go-plist"
	// "os"

	// "encoding/xml"

	"encoding/hex"

	"testing"
)

func TestPlistDecode(t *testing.T) {
	// r, err := os.Open("../testdata/Admin2.plist")
	// defer r.Close()
	// if err != nil {
	// 	t.Fatalf("error reading Admin.plist, err=%s", err)
	// }
	// body, err := ioutil.ReadAll(r)
	// if err != nil {
	// 	t.Fatalf("issue w/ reader on Admin.plist, err=%s", err)
	// }

	// res := Chiroot{}

	// format, err := plist.Unmarshal(body, res)
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// fmt.Printf("format = %d\n", format)
	// fmt.Printf("res = %v\n", res)

	main()

	// res := Chiroot{}
	// e := xml.Unmarshal(body, &res)
	// if e != nil {
	// 	t.Fatal(e)
	// }
	// fmt.Println(res)

	s := "016897E1A0B8F2C3B134665C20A727B7A158E28F"
	d, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%s\n", d)
}
