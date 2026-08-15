package oauth

import (
	"testing"
	"time"
)

// TestProactiveWaitShortLivedToken is the regression test for the refresh
// runaway. Authelia issues 10-minute access tokens; the old scheduler
// subtracted a fixed 10-minute proactiveWindow (on top of a 5-minute
// safetyWindow) from the expiry, so the computed wait was always negative
// and collapsed onto a 1-second floor. That produced ~2000 refreshes per
// hour per client — and since Authelia rotates the refresh token on every
// refresh, a single lost write anywhere in that chain forced a full
// device-code re-login.
func TestProactiveWaitShortLivedToken(t *testing.T) {
	now := time.Now()
	p := newTokenState(Tokens{AccessToken: "A", RefreshToken: "R", ExpiresIn: 600}, "", now)

	got := proactiveWait(p, now)
	if want := 7 * time.Minute; got != want {
		t.Fatalf("wait for a 10m token = %s, want %s", got, want)
	}
	if got <= minRefreshInterval {
		t.Fatalf("wait collapsed onto the floor (%s) — the runaway is back", got)
	}
}

func TestProactiveWaitClampsAndDefaults(t *testing.T) {
	now := time.Now()

	cases := []struct {
		name string
		tok  plaintextTokens
		want time.Duration
	}{
		{
			name: "long-lived token capped so failures surface early",
			tok:  newTokenState(Tokens{ExpiresIn: int((30 * 24 * time.Hour).Seconds())}, "", now),
			want: maxRefreshInterval,
		},
		{
			name: "missing expires_in falls back to the default lifetime",
			tok:  newTokenState(Tokens{ExpiresIn: 0}, "", now),
			want: time.Duration(float64(defaultLifetime) * refreshFraction),
		},
		{
			name: "negative expires_in cannot spin the loop",
			tok:  newTokenState(Tokens{ExpiresIn: -1}, "", now),
			want: time.Duration(float64(defaultLifetime) * refreshFraction),
		},
		{
			name: "already-expired token waits the floor, not a millisecond",
			tok:  plaintextTokens{issuedAt: now.Add(-2 * time.Hour), expiresAt: now.Add(-time.Hour)},
			want: minRefreshInterval,
		},
		{
			name: "legacy file without issued_at uses remaining lifetime",
			tok:  plaintextTokens{expiresAt: now.Add(10 * time.Minute)},
			want: 7 * time.Minute,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := proactiveWait(tc.tok, now); got != tc.want {
				t.Fatalf("wait = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestRefreshRateOverADay states the practical consequence in the units
// that matter: refreshes per day against Authelia's 10-minute tokens.
func TestRefreshRateOverADay(t *testing.T) {
	now := time.Now()
	p := newTokenState(Tokens{ExpiresIn: 600}, "", now)

	perDay := int(24 * time.Hour / proactiveWait(p, now))
	if perDay > 250 {
		t.Fatalf("%d refreshes/day against a 10m token — too many; each one rotates the refresh token", perDay)
	}
}
