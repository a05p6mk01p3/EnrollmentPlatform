package middleware

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Errors returned by validateJSONDocument. They are classified upstream into
// contract responses and never leak to clients as-is.
var (
	ErrMalformedJSON         = errors.New("malformed JSON")
	ErrMultipleJSONDocuments = errors.New("multiple JSON documents")
	ErrDuplicateJSONMember   = errors.New("duplicate JSON member")
)

// jsonFrame tracks one open JSON object/array during the token walk.
type jsonFrame struct {
	isObject bool
	// expectValue is used for objects only: false means the next token must be
	// a member name or '}'; true means the next token must be the member value.
	expectValue bool
	keys        map[string]struct{}
	// pendingKey is the member name whose value is currently being read
	// (objects only). It is used to derive the path of a nested object/array.
	pendingKey string
	// path is the sequence of object member names from the document root to
	// this object/array (arrays inherit their parent path; array elements add
	// no component). It is used to skip duplicate detection under specific
	// admitted opaque sub-trees.
	path []string
}

// validateJSONDocument verifies that r contains exactly one valid JSON value
// and that no JSON object contains duplicate member names.
//
// encoding/json does not detect either condition (json.Decoder ignores
// trailing documents and silently drops duplicate members), so this pre-pass
// runs before schema validation for sensitive mutations (Protocol v0.2.2
// SP-13). No regex is involved; the walk uses encoding/json's own tokenizer,
// which enforces JSON comma/string syntax.
func validateJSONDocument(r io.Reader) error {
	return validateJSONDocumentSkipping(r, nil)
}

// validateJSONDocumentSkipping is validateJSONDocument with a set of admitted
// opaque sub-tree paths where duplicate members are NOT rejected here. Those
// sub-trees carry identity-bearing raw JSON whose duplicate detection is owned
// by the downstream application boundary (which consumes the original bytes
// before JCS). skipPaths entries are root-relative sequences of object member
// names; a sub-tree is skipped when its path is exactly a skip path or a
// descendant of one.
func validateJSONDocumentSkipping(r io.Reader, skipPaths [][]string) error {
	dec := json.NewDecoder(r)
	dec.UseNumber()

	var stack []*jsonFrame
	rootDone := false

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			if len(stack) > 0 {
				return fmt.Errorf("%w: unexpected end of JSON document", ErrMalformedJSON)
			}
			if !rootDone {
				return fmt.Errorf("%w: empty document", ErrMalformedJSON)
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformedJSON, err)
		}
		if rootDone {
			return fmt.Errorf("%w: trailing data after JSON document", ErrMultipleJSONDocuments)
		}

		if len(stack) == 0 {
			// Top level: '{' or '[' opens the document; any scalar completes it.
			if d, ok := tok.(json.Delim); ok {
				if d == '{' || d == '[' {
					stack = append(stack, &jsonFrame{isObject: d == '{', keys: map[string]struct{}{}})
					continue
				}
				return fmt.Errorf("%w: unexpected delimiter %q", ErrMalformedJSON, d)
			}
			rootDone = true
			continue
		}

		top := stack[len(stack)-1]
		if top.isObject {
			if top.expectValue {
				if d, ok := tok.(json.Delim); ok {
					if d == '}' {
						return fmt.Errorf("%w: object member without value", ErrMalformedJSON)
					}
					if d == '{' || d == '[' {
						top.expectValue = false
						childPath := appendJSONPath(top.path, top.pendingKey)
						stack = append(stack, &jsonFrame{isObject: d == '{', keys: map[string]struct{}{}, path: childPath})
						continue
					}
					return fmt.Errorf("%w: unexpected delimiter %q", ErrMalformedJSON, d)
				}
				top.expectValue = false
				top.pendingKey = ""
				continue
			}

			// Expect a member name or '}'.
			if d, ok := tok.(json.Delim); ok && d == '}' {
				stack = stack[:len(stack)-1]
				if len(stack) == 0 {
					rootDone = true
				}
				continue
			}
			key, ok := tok.(string)
			if !ok {
				return fmt.Errorf("%w: object member name must be a string", ErrMalformedJSON)
			}
			if !jsonPathSkipped(top.path, skipPaths) {
				if _, dup := top.keys[key]; dup {
					return fmt.Errorf("%w: %q", ErrDuplicateJSONMember, key)
				}
				top.keys[key] = struct{}{}
			}
			top.pendingKey = key
			top.expectValue = true
			continue
		}

		// Array frame: values and ']' only; comma placement is enforced by
		// the tokenizer itself.
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case ']':
				stack = stack[:len(stack)-1]
				if len(stack) == 0 {
					rootDone = true
				}
			case '{', '[':
				stack = append(stack, &jsonFrame{isObject: d == '{', keys: map[string]struct{}{}, path: top.path})
			default:
				return fmt.Errorf("%w: unexpected delimiter %q", ErrMalformedJSON, d)
			}
			continue
		}
		// Scalar value inside an array is fine.
	}
}

// appendJSONPath returns parent extended by key, copying to avoid aliasing the
// parent slice across concurrently-walked frames.
func appendJSONPath(parent []string, key string) []string {
	out := make([]string, len(parent)+1)
	copy(out, parent)
	out[len(parent)] = key
	return out
}

// jsonPathSkipped reports whether path is exactly a skip path or a descendant
// of one.
func jsonPathSkipped(path []string, skipPaths [][]string) bool {
	for _, sp := range skipPaths {
		if len(path) < len(sp) {
			continue
		}
		match := true
		for i := range sp {
			if path[i] != sp[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
