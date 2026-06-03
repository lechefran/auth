package auth

import "time"

// Clock supplies time for auth workflows.
//
// It is injectable so tests can avoid sleeps and production code can use the
// system clock by default.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time {
	return time.Now().UTC()
}
