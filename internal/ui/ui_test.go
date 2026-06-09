package ui

import (
	"testing"
)

func TestFmtSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		bytes int64
		want  string
	}{
		{0, "0 B"},
		{500, "500 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1024*1024 - 1, "1024.0 KB"},
		{1024 * 1024, "1.0 MB"},
		{1024*1024 + 512*1024, "1.5 MB"},
		{10 * 1024 * 1024, "10.0 MB"},
	}

	for _, tc := range tests {
		got := FmtSize(tc.bytes)
		if got != tc.want {
			t.Errorf("FmtSize(%d) = %q, want %q", tc.bytes, got, tc.want)
		}
	}
}
