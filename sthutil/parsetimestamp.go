
package sthutil

import "time"

const (
	millisPerSecond     = uint64(time.Second / time.Millisecond)
	nanosPerMillisecond = uint64(time.Millisecond / time.Nanosecond)
)

func SthTimestampToTime(timestamp uint64) time.Time {
	//Defined as the current NTP Time [RFC5905], measured since the epoch (January 1, 1970, 00:00), ignoring leap seconds, in milliseconds.
	sec := timestamp / millisPerSecond
	nsec := (timestamp % millisPerSecond) * nanosPerMillisecond
	return time.Unix(int64(sec), int64(nsec))
}