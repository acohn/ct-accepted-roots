//go:generate go run log_list_gen.go -timeout 15

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

func (l Log) LogID() LogID {
	return LogID(logid.FromPubKeyB64OrDie(l.Key))
}

func (l Log) logIDSlice() []byte {
	logIDArr := l.LogID()
	return []byte(logIDArr[:])
}

func (l Log) LogIDString() string {
	return base64.StdEncoding.EncodeToString(l.logIDSlice())
}

func (l Log) KeyDER() ([]byte, error) {
	return base64.StdEncoding.DecodeString(l.Key)
}

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

type LogList struct {
	Logs []Log `json:"logs"`
}

func (l LogList) Sort() {
	sort.Slice(l.Logs, func(i, j int) bool { return strings.Compare(l.Logs[i].LogIDString(), l.Logs[j].LogIDString()) < 0 })
}
