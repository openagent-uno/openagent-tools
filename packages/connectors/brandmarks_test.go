package connectors

import (
	"bytes"
	"strings"
	"testing"
)

func TestBrandmarksAreClosedCanonicalVectors(t *testing.T) {
	entries, err := brandmarkFiles.ReadDir("brandmarks")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 || len(entries) != len(brandmarkPaths) {
		t.Fatal("brandmark asset and provider inventory differ")
	}
	paths := map[string]bool{}
	for id, path := range brandmarkPaths {
		if paths[path] {
			t.Fatalf("duplicate asset binding for %s", id)
		}
		paths[path] = true
		value := Brandmark(id)
		if value == "" || !validBrandmarkSVG([]byte(value)) {
			t.Fatalf("invalid embedded mark for %s", id)
		}
	}
	for _, entry := range entries {
		if entry.IsDir() || !paths["brandmarks/"+entry.Name()] {
			t.Fatal("unmapped brandmark asset")
		}
	}
}

func TestBrandmarkRejectsUntrustedSVGShapes(t *testing.T) {
	valid := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path fill="#123ABC" d="M0 0h24v24H0z"/></svg>`
	if !validBrandmarkSVG([]byte(valid)) {
		t.Fatal("canonical vector rejected")
	}
	cases := map[string][]byte{
		"script":           []byte(strings.Replace(valid, "<path", "<script>bad</script><path", 1)),
		"event":            []byte(strings.Replace(valid, "<path", `<path onload="bad"`, 1)),
		"external_ref":     []byte(strings.Replace(valid, "<path", `<path href="https://example.invalid/"`, 1)),
		"xlink":            []byte(strings.Replace(valid, "<path", `<path xlink:href="#other"`, 1)),
		"external_fill":    []byte(strings.Replace(valid, "#123ABC", "url(https://example.invalid/)", 1)),
		"style":            []byte(strings.Replace(valid, "<path", `<path style="fill:red"`, 1)),
		"transform":        []byte(strings.Replace(valid, "<path", `<path transform="scale(2)"`, 1)),
		"foreign_object":   []byte(strings.Replace(valid, "<path", "<foreignObject/><path", 1)),
		"doctype":          []byte(`<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///private">]>` + valid),
		"entity":           []byte(strings.Replace(valid, "M0", "&x;M0", 1)),
		"namespace_dots":   []byte(strings.Replace(valid, "www.w3.org", "wwwXw3Yorg", 1)),
		"trailing_newline": []byte(valid + "\n"),
		"namespace":        []byte(strings.Replace(valid, "http://www.w3.org/2000/svg", "https://example.invalid/", 1)),
		"viewbox":          []byte(strings.Replace(valid, "0 0 24 24", "0 0 100000 100000", 1)),
		"extra_path":       []byte(strings.Replace(valid, "</svg>", `<path fill="#123ABC" d="M0 0z"/></svg>`, 1)),
		"invalid_utf8":     append([]byte{0xff}, []byte(valid)...),
		"oversize":         []byte(strings.Replace(valid, "M0 0h24v24H0z", "M"+strings.Repeat("0 ", brandmarkMaximumBytes), 1)),
		"xml_prefix":       []byte(`<?xml version="1.0"?>` + valid),
		"trailing_data":    []byte(valid + "hidden"),
		"path_markup":      []byte(strings.Replace(valid, "M0 0h24v24H0z", `<image href="bad"/>`, 1)),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if validBrandmarkSVG(raw) {
				t.Fatal("untrusted SVG accepted")
			}
		})
	}
}

func TestBrandmarkExactIDAndIndependentReturnedValue(t *testing.T) {
	for _, id := range []string{"", "CODA", "../coda", "coda.svg", "https://example.invalid/coda", "fathom"} {
		if Brandmark(id) != "" {
			t.Fatal("unknown or unverified brand identity resolved")
		}
	}
	value := Brandmark("coda")
	if value == "" {
		t.Fatal("known mark missing")
	}
	copy := []byte(value)
	copy[0] = 'x'
	if Brandmark("coda") != value || bytes.Equal(copy, []byte(value)) {
		t.Fatal("returned value aliases mutable asset bytes")
	}
}
