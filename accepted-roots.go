package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"github.com/acohn/ct-accepted-roots/get"
	"github.com/acohn/ct-accepted-roots/httpclient"
	"github.com/acohn/ct-accepted-roots/loglist"
	"github.com/acohn/ct-accepted-roots/pkixstring"
	"log"
	"net/http"
	"sync"
	"time"
)

type logAcceptsRoot struct {
	log  *loglist.Log
	root *x509.Certificate
}

type fprToCertMap map[[sha256.Size]byte]*x509.Certificate

type rootfprToLogMap map[[sha256.Size]byte][]*loglist.Log

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	hc, err := httpclient.Build()
	if err != nil {
		log.Fatal(err)
	}
	fcm, rflm := getRootsFromLogs(ctx, loglist.Logs, hc)

	for rootfpr, ctlogs := range rflm {
		cert := fcm[rootfpr]
		fmt.Printf("%v,FP=%x\n", pkixstring.RDNSequenceToString(cert.Subject.ToRDNSequence()), sha256.Sum256(cert.Raw))
		for _, ctlog := range ctlogs {
			fmt.Printf("   %v, %v, [0x%x]\n", ctlog.Description, ctlog.Url, ctlog.LogID())
		}
		fmt.Println()

	}
}

func getRootsFromLogs(ctx context.Context, logs []loglist.Log, hc *http.Client) (fprToCertMap, rootfprToLogMap) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	wg := new(sync.WaitGroup)
	res := make(chan logAcceptsRoot)

	for _, ctLog := range logs {
		wg.Add(1)
		go getRootsFromLog(ctx, ctLog, hc, wg, res)
	}

	go func() {
		wg.Wait()
		close(res)
	}()

	knownRoots := make(fprToCertMap)            //map of root fingerprints to roots we've seen
	logsAcceptingRoots := make(rootfprToLogMap) //map of cert fingerprints to slice of ptrs to logs
	for accRoot := range res {
		rootFpr := sha256.Sum256(accRoot.root.Raw)
		knownRoots[rootFpr] = accRoot.root
		logsAcceptingRoots[rootFpr] = append(logsAcceptingRoots[rootFpr], accRoot.log)
	}
	return knownRoots, logsAcceptingRoots

}

func getRootsFromLog(ctx context.Context, ctLog loglist.Log, hc *http.Client, wg *sync.WaitGroup, res chan logAcceptsRoot) {
	defer wg.Done()
	roots, err := get.OneLog(ctx, hc, ctLog)
	if err != nil {
		log.Printf("Error while fetching from log %q: %v\n", ctLog.Description, err)
		return
	}
	for _, root := range roots {
		res <- logAcceptsRoot{log: &ctLog, root: root}
	}
}
