// Package idutil generates container IDs and names.
package idutil

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
)

func NewID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func Short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

var nameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)

func ValidateName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("invalid name %q: must match %s", name, nameRE)
	}
	return nil
}

var adjectives = []string{"brave", "calm", "eager", "fast", "gentle", "happy", "keen", "lucid", "quiet", "swift"}
var nouns = []string{"bpf", "mprog", "packet", "peer", "primary", "queue", "redirect", "scrub", "socket", "verdict"}

// RandomName returns a docker-style "adjective_noun" name.
func RandomName() string {
	b := make([]byte, 2)
	_, _ = rand.Read(b)
	return adjectives[int(b[0])%len(adjectives)] + "_" + nouns[int(b[1])%len(nouns)]
}
