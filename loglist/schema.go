//go:generate go run log_list_gen.go -timeout 15

// BUG(acohn): The log list is currently manually updated. If you want to add a log,
// run go generate and send a pull request.

// Package loglist contains a list of all known working CT logs, as a helper for other
// projects that wish to fetch from all CT logs. The canonical log list pulls from three
// different sources to find the currently-functional logs.
package loglist

import (
	"encoding/base64"
	"fmt"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/logid"
	"net/http"
	"sort"
	"strings"
	"sync"
)

type Log struct {
	Description       string  `json:"description"`
	Key               string  `json:"key"`
	MaximumMergeDelay float64 `json:"maximum_merge_delay"`
	Url               string  `json:"url"`
}

// LogID returns the log ID (the SHA256 hash of the log's key)
func (l Log) LogID() logid.LogID {
	return logid.FromPubKeyB64OrDie(l.Key)
}

// LogIDString returns the printable log ID - the Base64 encoded SHA256 hash of the log key.
func (l Log) LogIDString() string {
	return base64.StdEncoding.EncodeToString(l.LogID().Bytes())
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

var idToLog map[logid.LogID]*Log
var idToLogOnce sync.Once

func ByLogID(id logid.LogID) (*Log, error) {
	idToLogOnce.Do(func() {
		idToLog = make(map[logid.LogID]*Log)
		for idx := range Logs {
			idToLog[Logs[idx].LogID()] = &Logs[idx]
		}
	})
	if ctlog, ok := idToLog[id]; ok {
		return ctlog, nil
	} else {
		return nil, fmt.Errorf("Could not find %s", id.String())
	}
}

func ByLogIdStr(idStr string) (*Log, error) {
	logID, err := logid.FromB64(idStr)
	if err != nil {
		return nil, err
	}
	return ByLogID(logID)
}

var urlToLog map[string]*Log
var urlToLogOnce sync.Once

func ByLogURL(url string) (*Log, error) {
	urlToLogOnce.Do(func() {
		urlToLog = make(map[string]*Log)
		for idx := range Logs {
			urlToLog[Logs[idx].Url] = &Logs[idx]
		}
	})

	url = strings.TrimPrefix(url, "https://") //normalize

	if ctlog, ok := urlToLog[url]; ok {
		return ctlog, nil
	} else {
		return nil, fmt.Errorf("Could not find log with URL %s", url)
	}
}

// LogList is a slice of logs with a defined sort order
type LogList []Log

// Sorts a LogList's slice of logs lexicographically by the log ID, to ensure stable ordering and sane diffs.
func (l LogList) Sort() {
	sort.Slice(l, func(i, j int) bool { return strings.Compare(l[i].LogIDString(), l[j].LogIDString()) < 0 })
}
