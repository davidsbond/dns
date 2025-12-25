// Package list provides the primitives for in-memory block and allow lists for DNS resolution. By default, a very strict
// block and allow list are embedded into the binary. These can be updated using "go generate".
package list

import (
	"bufio"
	"context"
	"embed"
	"io"
	"strings"

	"github.com/davidsbond/x/set"
)

var (
	//go:embed data/*.txt
	data embed.FS
)

// Block returns a set of all domains contained within the block list.
func Block(ctx context.Context) (*set.Set[string], error) {
	file, err := data.Open("data/block.txt")
	if err != nil {
		return nil, err
	}

	return parseEntries(ctx, file)
}

// Allow returns a set of all domains contained within the allow list.
func Allow(ctx context.Context) (*set.Set[string], error) {
	file, err := data.Open("data/allow.txt")
	if err != nil {
		return nil, err
	}

	return parseEntries(ctx, file)
}

func parseEntries(ctx context.Context, r io.Reader) (*set.Set[string], error) {
	entries := set.New[string]()

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		if err := scanner.Err(); err != nil {
			return nil, err
		}

		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}

		entries.Put(line)
	}

	return entries, nil
}
