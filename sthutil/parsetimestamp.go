// sthutil contains functions for converting STH timestamps from and to native Go times.
package sthutil

import "time"

const (
	millisPerSecond     = uint64(time.Second / time.Millisecond)
	nanosPerMillisecond = uint64(time.Millisecond / time.Nanosecond)
)

// SthTimestampToTime converts a STH timestamp to a native Go time.
func SthTimestampToTime(timestamp uint64) time.Time {
	//Defined as the current NTP Time [RFC5905], measured since the epoch (January 1, 1970, 00:00), ignoring leap seconds, in milliseconds.
	sec := timestamp / millisPerSecond
	nsec := (timestamp % millisPerSecond) * nanosPerMillisecond
	return time.Unix(int64(sec), int64(nsec))
}

// TimeToSthTimestamp converts a Go time to a STH timestamp. Note that this is not a lossless conversion:
// Go times are nanosecond precision, while STH timestamps are only precise to the millisecond.
func TimeToSthTimestamp(ts time.Time) uint64 {
	return (uint64(ts.UnixNano()) / nanosPerMillisecond)
}
