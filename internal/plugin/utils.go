package plugin

import (
	"bytes"
	"io"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// cleanupUTF16 converts a byte slice (expected to be UTF-16-LE) to a Go string,
// removing null terminators and handling potential garbage.
func cleanupUTF16(b []byte) string {
	if len(b)%2 != 0 {
		return string(b)
	}

	u16s := make([]uint16, len(b)/2)
	for i := 0; i < len(u16s); i++ {
		u16s[i] = uint16(b[i*2]) | (uint16(b[i*2+1]) << 8)
	}

	runes := utf16.Decode(u16s)
	// Trim nulls
	if len(runes) > 0 && runes[len(runes)-1] == 0 {
		runes = runes[:len(runes)-1]
	}
	// Also stop at first null if embedded?
	for i, r := range runes {
		if r == 0 {
			return string(runes[:i])
		}
	}
	return string(runes)
}

// BytesToString tries to convert bytes to string using UTF-8 first,
// and falls back to GB18030 (superset of GBK including rare characters) if invalid.
func BytesToString(b []byte) string {
	// 1. Try UTF-8
	if utf8.Valid(b) {
		return string(b)
	}
	// 2. Try GB18030
	reader := transform.NewReader(bytes.NewReader(b), simplifiedchinese.GB18030.NewDecoder())
	d, err := io.ReadAll(reader)
	if err == nil {
		return string(d)
	}
	// 3. Last result: raw string (garbage)
	return string(b)
}

// CleanString cleans up a string that might be garbage or GBK encoded but already cast to string.
// If the string contains Replacement Characters (indicating failed UTF-8 decode), it might mean
// it was originally GBK bytes interpreted as UTF-8. However, recovering that is hard if we don't have original bytes.
// Best use BytesToString when we have raw bytes.
// This function trims nulls and spaces.
func CleanString(s string) string {
	return strings.TrimSpace(strings.Trim(s, "\x00"))
}

// windowsFiletimeToGo converts a Windows FILETIME (uint64) to a Go time.Time.
func windowsFiletimeToGo(ft uint64) time.Time {
	// 100-nanosecond intervals since January 1, 1601 (UTC)
	const intervalsPerSecond = 10000000
	// Seconds between 1601-01-01 and 1970-01-01
	seconds := int64(ft / intervalsPerSecond)
	nanos := int64(ft%intervalsPerSecond) * 100
	seconds -= 11644473600
	t := time.Unix(seconds, nanos).UTC()
	if t.Year() < 1601 || t.Year() > 3000 {
		return time.Time{}
	}
	return t
}
