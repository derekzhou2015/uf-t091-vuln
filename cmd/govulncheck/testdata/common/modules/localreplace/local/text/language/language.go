// Package language is a local stub used to exercise govulncheck against a
// filesystem replace directive. It deliberately keeps the import path and
// symbol named by GO-2021-0113 so the local vulnerability database matches.
package language

// Parse mirrors the vulnerable symbol covered by GO-2021-0113.
func Parse(s string) (string, error) {
	return s, nil
}
