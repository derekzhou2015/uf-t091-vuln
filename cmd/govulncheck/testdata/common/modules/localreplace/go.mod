module golang.org/localreplace

go 1.20

require golang.org/x/text v0.3.0

// Explicitly versioned filesystem replacement: the go command records the
// declared version on the outer module but gives the replacement a local
// directory path and no version.
replace golang.org/x/text v0.3.0 => ./local/text
