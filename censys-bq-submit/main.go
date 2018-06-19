package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"

	"cloud.google.com/go/bigquery"
	"github.com/acohn/ct-accepted-roots/loglist"
	"github.com/google/certificate-transparency-go"
	ct_client "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/juju/ratelimit"
	"golang.org/x/net/context"
	"google.golang.org/api/iterator"
)

const (
	projectID   = "universal-talon-184518"
	datasetName = "ct_tables"
)

type censysBQRow struct {
	Raw  string   `bigquery:"raw,nullable"`
	Tags []string `bigquery:"tags"`
}

type addRequest struct {
	isPreCert bool
	chain     []ct.ASN1Cert
}

func main() {
	var pbFile string
	var logUrl string
	var tableName string
	flag.StringVar(&tableName, "table", "", "table name to pull results from")
	flag.StringVar(&pbFile, "t", "", "protobuf-format temporal log spec file; if set, overrides -l")
	flag.StringVar(&logUrl, "l", "ct.googleapis.com/skydiver", "CT log to use")
	flag.Parse()

	ctx := context.Background()

	var log_client ct_client.AddLogClient

	ht := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}

	hc := &http.Client{Timeout: 15 * time.Second, Transport: ht}

	if pbFile != "" {
		cfg, err := ct_client.TemporalLogConfigFromFile(pbFile)
		if err != nil {
			log.Fatal(err)
		}
		log_client, err = ct_client.NewTemporalLogClient(*cfg, hc)
		if err != nil {
			log.Fatal(err)
		}

	} else {
		ctLog, err := loglist.ByLogURL(logUrl)
		if err != nil {
			log.Fatalf("Failed to find a log to use: %v", err)
		}
		log_client, err = ctLog.Client(hc)
		if err != nil {
			log.Fatalf("Failed to create a CT log client: %v", err)
		}
	}

	intermediatePool, err := genIntermediatesPool("intermediates")
	if err != nil {
		log.Fatal(err)
	}

	rootPool, err := genRootsPool(ctx, log_client)
	if err != nil {
		log.Fatal(err)
	}

	wg := new(sync.WaitGroup)

	bqClient, err := bigquery.NewClient(ctx, projectID)
	if err != nil {
		log.Fatalf("Failed to create BigQuery client: %v\n", err)
	}

	it := bqClient.Dataset(datasetName).Table(tableName).Read(ctx)

	certChan := make(chan addRequest)

	limiter := ratelimit.NewBucket(100*time.Millisecond, 10)
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			for chain := range certChan {
				limiter.Wait(1)
				if chain.isPreCert {
					_, err = log_client.AddPreChain(ctx, chain.chain)
				} else {
					_, err = log_client.AddChain(ctx, chain.chain)
				}
				if err != nil {
					log.Print(err)
				}
			}
		}()
	}

	for {
		row := new(censysBQRow)
		err := it.Next(row)
		if err == iterator.Done {
			break
		}
		if err != nil {
			log.Fatalf("Error retrieving row: %v\n", err)
		}
		cert, err := base64StrToCert(row.Raw)
		if err != nil {
			log.Printf("Error parsing certificate: %v\n", err)
			continue
		}
		cert.UnhandledCriticalExtensions = nil
		isPreCert := false
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(x509.OIDExtensionCTPoison) {
				isPreCert = true
				break
			}
		}

		/*if cert.Issuer.CommonName != "Western Digital Technologies Certification Authority" {
			continue
		}*/

		if len(cert.DNSNames) > 0 {
			log.Printf("Hostname: %v, https://crt.sh/?q=%x\n", cert.DNSNames[0], sha256.Sum256(cert.Raw))
		} else {
			log.Printf("CN: %v, https://crt.sh/?q=%x\n", cert.Subject.CommonName, sha256.Sum256(cert.Raw))
		}

		verifyOpts := x509.VerifyOptions{
			Roots:             rootPool,
			Intermediates:     intermediatePool,
			DisableTimeChecks: true,
			KeyUsages:         []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		chains, err := cert.Verify(verifyOpts)
		if err != nil {
			log.Print(err)
			log.Printf("SN: %v\n", cert.SerialNumber.Text(10))
			continue
		}

		for _, chain := range chains {
			asn1chain := make([]ct.ASN1Cert, 0, len(chain))
			for _, cert := range chain {
				asn1chain = append(asn1chain, ct.ASN1Cert{Data: cert.Raw})
			}
			certChan <- addRequest{
				isPreCert: isPreCert,
				chain:     asn1chain,
			}
			break
		}
	}
	close(certChan)
	wg.Wait()

}

func base64StrToCert(certStr string) (*x509.Certificate, error) {
	decoded, err := base64.StdEncoding.DecodeString(certStr)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(decoded)
}

func genRootsPool(ctx context.Context, cl ct_client.AddLogClient) (*x509.CertPool, error) {
	var ASN1Roots []ct.ASN1Cert
	for i := 0; ; i++ {
		var err error
		ASN1Roots, err = cl.GetAcceptedRoots(ctx)
		if err == nil {
			break
		} else if i > 10 {
			return nil, err
		}
	}

	ret := x509.NewCertPool()

	for _, ASN1Root := range ASN1Roots {
		root, err := x509.ParseCertificate(ASN1Root.Data)
		if err != nil {
			log.Print(err)
		}
		if root != nil {
			ret.AddCert(root)
		}
	}
	return ret, nil
}

func genIntermediatesPool(filename string) (*x509.CertPool, error) {
	intermediatesPEM, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	certpool := x509.NewCertPool()

	for len(intermediatesPEM) > 0 {
		var block *pem.Block
		block, intermediatesPEM = pem.Decode(intermediatesPEM)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		cert.UnhandledCriticalExtensions = nil //Don't worry about unhandled critical extensions - we aren't verifying for purposes of trust
		certpool.AddCert(cert)
	}
	return certpool, nil
}
