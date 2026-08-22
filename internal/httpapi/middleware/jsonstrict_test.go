package middleware

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateJSONDocumentAccepts(t *testing.T) {
	cases := []string{
		`{}`,
		`{"a":1}`,
		`{"a":{"b":[1,2,3]}}`,
		`[1,2,{"x":true}]`,
		`[]`,
		`"scalar"`,
		`123`,
		`null`,
		`true`,
		`{"a":1}` + "\n\t ",
		`{"a":[{"n":1},{"n":2}],"b":"x"}`,
	}
	for _, in := range cases {
		if err := validateJSONDocument(strings.NewReader(in)); err != nil {
			t.Errorf("validateJSONDocument(%q) = %v, want nil", in, err)
		}
	}
}

func TestValidateJSONDocumentRejectsMalformed(t *testing.T) {
	cases := []string{
		``,
		`{`,
		`{"a":}`,
		`{"a"`,
		`{"a":1,}`,
		`[1,]`,
		`]`,
		`}`,
		`{"a" 1}`,
		`{"a":1 "b":2}`,
		`{1:2}`,
		`{"a":]}`,
		`nul`,
	}
	for _, in := range cases {
		err := validateJSONDocument(strings.NewReader(in))
		if err == nil {
			t.Errorf("validateJSONDocument(%q) = nil, want error", in)
			continue
		}
		if !errors.Is(err, ErrMalformedJSON) {
			t.Errorf("validateJSONDocument(%q) = %v, want ErrMalformedJSON", in, err)
		}
	}
}

func TestValidateJSONDocumentRejectsDuplicates(t *testing.T) {
	cases := []string{
		`{"a":1,"a":2}`,
		`{"a":{"b":1,"b":2}}`,
		`[{"x":1,"x":2}]`,
		`{"a":1,"b":2,"a":3}`,
		// Unicode-escaped member names decode before comparison (audit case I).
		`{"a":1,"\u0061":2}`,
		`{"\u0061":1,"a":2}`,
	}
	for _, in := range cases {
		err := validateJSONDocument(strings.NewReader(in))
		if err == nil {
			t.Errorf("validateJSONDocument(%q) = nil, want duplicate error", in)
			continue
		}
		if !errors.Is(err, ErrDuplicateJSONMember) {
			t.Errorf("validateJSONDocument(%q) = %v, want ErrDuplicateJSONMember", in, err)
		}
	}
}

func TestValidateJSONDocumentRejectsTrailingDocuments(t *testing.T) {
	cases := []string{
		`{} {}`,
		"{\"a\":1}\n{\"b\":2}",
		`1 2`,
		`"a" "b"`,
		`[] []`,
	}
	for _, in := range cases {
		err := validateJSONDocument(strings.NewReader(in))
		if err == nil {
			t.Errorf("validateJSONDocument(%q) = nil, want trailing-document error", in)
			continue
		}
		if !errors.Is(err, ErrMultipleJSONDocuments) {
			t.Errorf("validateJSONDocument(%q) = %v, want ErrMultipleJSONDocuments", in, err)
		}
	}
}
