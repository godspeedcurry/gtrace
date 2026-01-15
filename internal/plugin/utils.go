package plugin

import (
	"time"
	"unicode/utf16"
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
