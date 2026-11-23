// Package sbom renders a sorted package list into standards based SBOM
// documents (CycloneDX 1.5 and SPDX 2.3) with deterministic identifiers.
package sbom

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"
)

// namespaceUUID is a fixed, tool specific UUID namespace used to derive
// deterministic version 5 UUIDs for generated documents. RFC 4122 recommends
// pre-generating one namespace per application.
const namespaceUUID = "9d24c0e5-6d1a-4b8f-9c3e-2f7a1b4d5e6f"

// uuidV5 derives a deterministic RFC 4122 version 5 UUID (SHA 1 based, as the
// standard specifies) from namespaceUUID and name. Identical inputs always
// produce identical UUIDs, so rescanning an unchanged dependency tree yields
// identical document identifiers.
func uuidV5(name string) string {
	ns, err := hex.DecodeString(strings.ReplaceAll(namespaceUUID, "-", ""))
	if err != nil {
		// Unreachable: namespaceUUID is a compile time constant of hex digits.
		panic("sbom: invalid namespace UUID: " + err.Error())
	}
	h := sha1.New()
	h.Write(ns) //nolint:gosec // UUIDv5 is defined over SHA 1 by RFC 4122.
	h.Write([]byte(name))
	sum := h.Sum(nil)[:16]
	sum[6] = (sum[6] & 0x0f) | 0x50 // version 5
	sum[8] = (sum[8] & 0x3f) | 0x80 // RFC 4122 variant
	return formatUUID(sum)
}

// formatUUID renders 16 bytes as the canonical lowercase 8-4-4-4-12 form.
func formatUUID(b []byte) string {
	s := hex.EncodeToString(b)
	return strings.Join([]string{s[0:8], s[8:12], s[12:16], s[16:20], s[20:32]}, "-")
}
