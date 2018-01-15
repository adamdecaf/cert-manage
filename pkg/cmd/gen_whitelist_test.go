package cmd

import (
	"reflect"
	"testing"
)

func TestGenWhitelist_getChoices(t *testing.T) {
	// left off '-from file'
	choices := getChoices("", "/dev/null")
	if !reflect.DeepEqual(choices, []string{"file"}) {
		t.Errorf("got %q", choices)
	}

	// has '-from file'
	choices = getChoices("file", "/dev/null")
	if !reflect.DeepEqual(choices, []string{"file"}) {
		t.Errorf("got %q", choices)
	}

	// browser
	choices = getChoices("browser", "")
	if !reflect.DeepEqual(choices, []string{"browser"}) {
		t.Errorf("got %q", choices)
	}

	// comma separated list
	choices = getChoices("browser,file", "")
	if !reflect.DeepEqual(choices, []string{"browser", "file"}) {
		t.Errorf("got %q", choices)
	}
}
