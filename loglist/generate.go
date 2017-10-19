//go:generate go run generate.go -loglists https://www.gstatic.com/ct/log_list/all_logs_list.json,https://ct.grahamedgecombe.com/logs.json
// +build ignore
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"github.com/acohn/ct-accepted-roots/loglist/schema"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/logid"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var loglists = flag.String("loglists", "https://ct.grahamedgecombe.com/logs.json,https://www.gstatic.com/ct/log_list/all_logs_list.json", "Comma-separated list of log URLs")

func main() {
	knownLogs := make(map[logid.LogID]schema.Logs)

	flag.Parse()
	//Grab each log list
	loglists := strings.Split(*loglists, ",")

	for _, listUrl := range loglists {
		logList, err := fetchAndParseLogList(listUrl)
		if err != nil {
			log.Fatal(err)
		}
		for _, log := range logList.Logs {
			if logurl, err := url.Parse(log.Url); err == nil {
				if logurl.Scheme == "" {
					logurl.Scheme = "https"
				}
				log.Url = logurl.String()
			}
			logID := logid.FromPubKeyB64OrDie(log.Key)
			knownLogs[logID] = log
		}
	}

	//attempt to connect to each one
	workingLogChan := make(chan logid.LogID, len(knownLogs))
	wg := new(sync.WaitGroup)
	for logID, log := range knownLogs {
		wg.Add(1)
		//log, logID := log, logID //Make copies so the goroutine doesn't get stale versions
		go testLog(log, logID, workingLogChan, wg)
	}

	go func() {
		wg.Wait()
		close(workingLogChan)
	}()

	workingLogs := []schema.Logs{}

	for logID := range workingLogChan {
		workingLogs = append(workingLogs, knownLogs[logID])
	}

	//for the ones that succeed, write to the all_logs.json file
	newJson, err := json.MarshalIndent(schema.Root{Logs: workingLogs}, "", "    ")
	if err != nil {
		log.Fatal(err)

	}
	err = ioutil.WriteFile("all_logs.json", newJson, 0777)
}

func fetchAndParseLogList(url string) (*schema.Root, error) {

	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	listJSON, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	logList := new(schema.Root)
	err = json.Unmarshal(listJSON, logList)
	if err != nil {
		log.Fatal(err)
	}
	return logList, nil

}

func testLog(ctLog schema.Logs, logID logid.LogID, workingLogChan chan logid.LogID, wg *sync.WaitGroup) {
	defer wg.Done()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second) //Only give a log five seconds to get back to us
	defer cancel()

	logKey, err := base64.StdEncoding.DecodeString(ctLog.Key)
	if err != nil {
		log.Printf("Failed to decode log key for log %v - this should not happen", ctLog.Url)
		return
	}
	client, err := client.New(ctLog.Url, nil, jsonclient.Options{PublicKeyDER: logKey})
	if err != nil {
		log.Printf("Could not create a new log client for log %v", ctLog.Url)
		return
	}
	sth, err := client.GetSTH(ctx)
	if err != nil {
		//assume the log is dead
		log.Printf("Error from log %v: %v", ctLog.Url, err)
		return
	}
	sthTimestamp := sthTimestampToTime(sth.Timestamp)
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
		log.Printf("Error from log %v: %v", ctLog.Url, err)
		return
	}
	if len(roots) == 0 {
		log.Printf("Log %v does not accept from any roots!", ctLog.Url)
		return
	}

	workingLogChan <- logID
	return
}

const (
	millisPerSecond     = uint64(time.Second / time.Millisecond)
	nanosPerMillisecond = uint64(time.Millisecond / time.Nanosecond)
)

func sthTimestampToTime(timestamp uint64) time.Time {
	//Defined as the current NTP Time [RFC5905], measured since the epoch (January 1, 1970, 00:00), ignoring leap seconds, in milliseconds.
	sec := timestamp / millisPerSecond
	nsec := (timestamp % millisPerSecond) * nanosPerMillisecond
	return time.Unix(int64(sec), int64(nsec))
}
