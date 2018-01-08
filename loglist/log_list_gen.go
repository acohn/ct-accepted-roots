// +build ignore

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"github.com/acohn/ct-accepted-roots/httpclient"
	"github.com/acohn/ct-accepted-roots/loglist"
	"github.com/acohn/ct-accepted-roots/sthutil"
	"github.com/google/certificate-transparency-go/logid"
	"go/format"
	"golang.org/x/net/context/ctxhttp"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"text/template"
	"time"
)

var logListUrls = flag.String("log_list_urls", "https://crt.sh/logs.json,https://ct.grahamedgecombe.com/logs.json,https://www.gstatic.com/ct/log_list/all_logs_list.json", "Comma-separated list of log URLs")
var timeout = flag.Int("timeout", 15, "Timeout for all HTTP responses")

func main() {
	flag.Parse()
	httpCl, err := httpclient.Build()
	if err != nil {
		log.Fatal("Could not build HTTP client")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeout)*time.Second)
	defer cancel()

	//Grab each log list
	knownLogs := make(map[logid.LogID]loglist.Log)
	logListUrls := strings.Split(*logListUrls, ",")

	for _, listUrl := range logListUrls {
		logList, err := fetchAndParseLogList(ctx, listUrl, httpCl)
		if err != nil {
			log.Fatal(err)
		}
		for _, ctlog := range logList {
			ctlog.Url = strings.TrimPrefix(ctlog.Url, "https://") //Edgecombe's and crt.sh's lists have https://; Google's doesn't.
			ctlog.Url = strings.TrimRight(ctlog.Url, "/")         //strip trailing slash

			knownLogs[ctlog.LogID()] = ctlog
		}
	}

	//attempt to connect to each one
	workingLogChan := make(chan logid.LogID, len(knownLogs))
	wg := new(sync.WaitGroup)
	for _, ctlog := range knownLogs {
		wg.Add(1)
		go testLog(ctx, ctlog, workingLogChan, wg, httpCl)
	}

	go func() {
		wg.Wait()
		close(workingLogChan)
	}()

	var working loglist.LogList

	for logID := range workingLogChan {
		working = append(working, knownLogs[logID])
	}

	//Sort the working logs by LogID, so we don't rearrange logs based on response time and make diffs evil.
	working.Sort()

	//for the ones that succeed, write to the all_logs.json file
	workingJSON := logListJSON{Logs: working}
	newJson, err := json.MarshalIndent(workingJSON, "", "    ")
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("all_logs.json", newJson, 0777)
	if err != nil {
		log.Fatal(err)
	}

	outputGoFile(working, logListUrls, "log_list.go")
	if err != nil {
		log.Fatal(err)
	}

}

type allLogsGoTmpl struct {
	Logs      []loglist.Log
	URLs      []string
	Timestamp time.Time
}

func (t *allLogsGoTmpl) TimestampStr() string {
	return t.Timestamp.Format(time.RFC1123)
}

func outputGoFile(logs []loglist.Log, urls []string, outputFile string) error {

	tmplText := `// Code generated by log_list_gen.go using go generate. DO NOT EDIT.
// Generated at
//  {{ .TimestampStr }}
// using data from{{ range .URLs }}
//  {{ . }}{{ end }}

package loglist

import "time"

var Timestamp = time.Date({{ .Timestamp.Year}},time.{{ .Timestamp.Month}},{{ .Timestamp.Day}},{{ .Timestamp.Hour}},{{ .Timestamp.Minute}},{{ .Timestamp.Second}},0,time.UTC)

var Logs = LogList{
{{ range .Logs }}{
Key: "{{ .Key }}",
Description: {{ printf "%#v" .Description }}, // {{.LogIDString}}
Url: {{ printf "%#v" .Url }},
MaximumMergeDelay: {{ .MaximumMergeDelay }},
},
{{ end }}}
`

	allLogsGo := &allLogsGoTmpl{logs, urls, time.Now().UTC()}

	buf := new(bytes.Buffer)

	tmpl, err := template.New("log_list.go").Parse(tmplText)
	if err != nil {
		return err
	}
	err = tmpl.Execute(buf, allLogsGo)
	if err != nil {
		return err
	}
	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(outputFile, formatted, 0644)
	return err
}

// logListJSON holds a slice of logs for unmarshalling
type logListJSON struct {
	Logs loglist.LogList `json:"logs"`
}

func fetchAndParseLogList(ctx context.Context, url string, hc *http.Client) (loglist.LogList, error) {

	resp, err := ctxhttp.Get(ctx, hc, url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	listJSON, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	logList := new(logListJSON)
	err = json.Unmarshal(listJSON, logList)
	if err != nil {
		log.Fatal(err)
	}
	return logList.Logs, nil

}

func testLog(ctx context.Context, ctLog loglist.Log, workingLogChan chan logid.LogID, wg *sync.WaitGroup, hc *http.Client) {
	defer wg.Done()

	client, err := ctLog.Client(hc)
	if err != nil {
		log.Printf("Could not create a new log client for log %v", ctLog.Url)
		return
	}
	sth, err := client.GetSTH(ctx)
	if err != nil {
		//assume the log is dead
		log.Printf("Error fetching STH from log %v: %v", ctLog.Url, err)
		return
	}
	sthTimestamp := sthutil.SthTimestampToTime(sth.Timestamp)
	if sthTimestamp.After(time.Now()) {
		log.Printf("STH from log %v is in the future by %v!", ctLog.Url, sthTimestamp.Sub(time.Now()))
		return
	}
	if sthTimestamp.Before(time.Now().Add(time.Duration(ctLog.MaximumMergeDelay) * time.Second * -1)) {
		log.Printf("Latest STH from log %v (%v) blows the MMD!", ctLog.Url, sthTimestamp)
		return
	}
	roots, err := client.GetAcceptedRoots(ctx)
	if err != nil {
		//assume the log is dead
		log.Printf("Error fetching accepted certs from log %v: %v", ctLog.Url, err)
		return
	}
	if len(roots) == 0 {
		log.Printf("Log %v does not accept from any roots!", ctLog.Url)
		return
	}

	workingLogChan <- ctLog.LogID()
	return
}
