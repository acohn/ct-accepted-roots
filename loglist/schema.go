//go:generate go run log_list_gen.go -timeout 15

// BUG(acohn): The log list is currently manually updated. If you want to add a log,
// run go generate and send a pull request.

// Package loglist contains a list of all known working CT logs, as a helper for other
// projects that wish to fetch from all CT logs. The canonical log list pulls from three
// different sources to find the currently-functional logs.
package loglist

import (
	"encoding/base64"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/logid"
	"net/http"
	"sort"
	"strings"
)

type Log struct {
	Description       string  `json:"description"`
	Key               string  `json:"key"`
	MaximumMergeDelay float64 `json:"maximum_merge_delay"`
	Url               string  `json:"url"`
}

//Alias the logID type so we don't have to import the CT logID everywhere
type LogID logid.LogID

// LogID returns the log ID (the SHA256 hash of the log's key)
func (l Log) LogID() LogID {
	return LogID(logid.FromPubKeyB64OrDie(l.Key))
}

// logIDSlice returns the log ID as a byte slice
func (l Log) logIDSlice() []byte {
	logIDArr := l.LogID()
	return []byte(logIDArr[:])
}

// LogIDString returns the printable log ID - the Base64 encoded SHA256 hash of the log key.
func (l Log) LogIDString() string {
	return base64.StdEncoding.EncodeToString(l.logIDSlice())
}

// KeyDER returns the log's key as a byte slice
func (l Log) KeyDER() ([]byte, error) {
	return base64.StdEncoding.DecodeString(l.Key)
}

// Client returns a LogClient with a nested *http.Client.
func (l Log) Client(hc *http.Client) (*client.LogClient, error) {
	logKey, err := l.KeyDER()
	if err != nil {
		return nil, err
	}
	url := l.Url
	if !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}
	logcli, err := client.New(url, hc, jsonclient.Options{PublicKeyDER: logKey})
	if err != nil {
		return nil, err
	}
	return logcli, nil
}

// LogList holds a slice of logs
type LogList struct {
	Logs []Log `json:"logs"`
}

// Sorts a LogList's slice of logs alphabetically by the log ID string, to ensure stable ordering and sane diffs.
func (l LogList) Sort() {
	sort.Slice(l.Logs, func(i, j int) bool { return strings.Compare(l.Logs[i].LogIDString(), l.Logs[j].LogIDString()) < 0 })
}
