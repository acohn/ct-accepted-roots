package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/acohn/ct-accepted-roots/loglist"
	ct_client "github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/fixchain"
	"github.com/google/certificate-transparency-go/fixchain/ratelimiter"
	"github.com/google/certificate-transparency-go/x509"
	retryablehttp "github.com/hashicorp/go-retryablehttp"
)

type CensysQuery struct {
	Query   string   `json:"query"`
	Page    int      `json:"page"`
	Fields  []string `json:"fields"`
	Flatten bool     `json:"flatten"`
}

type CensysResponse struct {
	Status   string                 `json:"status"`
	Metadata CensysResponseMetadata `json:"metadata"`
	Results  []CensysCertInfo       `json:"results"`
}

type CensysResponseMetadata struct {
	Count       int    `json:"count"`
	Query       string `json:"query"`
	BackendTime int    `json:"backend_time"`
	Page        int    `json:"page"`
	Pages       int    `json:"pages"`
}

type CensysCertInfo struct {
	Raw string `json:"raw"`
}

type CensysCreds struct {
	Uid    string `json:"uid"`
	Secret string `json:"secret"`
}

func (c CensysCertInfo) ToX509() (*x509.Certificate, error) {
	certDer, err := base64.StdEncoding.DecodeString(c.Raw)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDer)
	if cert != nil {
		return cert, nil
	}
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func main() {
	var pbFile string
	var logUrl string
	flag.StringVar(&pbFile, "t", "", "protobuf-format temporal log spec file; if set, overrides -l")
	flag.StringVar(&logUrl, "l", "ct.googleapis.com/skydiver", "CT log to use")
	flag.Parse()

	var log_client ct_client.AddLogClient

	hc := &http.Client{Timeout: 1 * time.Second}

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

	credsJSON, err := ioutil.ReadFile("creds.json")
	if err != nil {
		log.Fatal(err)
	}
	creds := &CensysCreds{}
	json.Unmarshal(credsJSON, &creds)

	logerrchain := make(chan *fixchain.FixError)
	go func() {
		for err := range logerrchain {
			log.Print(err)
		}
	}()

	logger := fixchain.NewLogger(context.Background(), 600, logerrchain, log_client, ratelimiter.NewLimiter(20), true)

	intermediatePool, err := genIntermediatesPool("intermediates")
	if err != nil {
		log.Fatal(err)
	}

	rootPool := logger.RootCerts()

	rhc := retryablehttp.NewClient()

	wg := new(sync.WaitGroup)

	censysQuery := `not tags.raw:"ct" and precert: false and tags.raw: "trusted" and not parsed.issuer.organization.raw: "Google UK Ltd."`

	var query = CensysQuery{
		Page:    1,
		Fields:  []string{"raw"},
		Flatten: true,
	}

	for prefix := 0; prefix < 16; prefix++ {
		log.Printf("Doing SHA256 prefix %01x", prefix)
		query.Query = fmt.Sprintf(`(%s) and parsed.fingerprint_sha256:/%01x.*/`, censysQuery, prefix)
		pageCount := 2
		for page := 1; page <= pageCount; page++ {
			query.Page = page
			var cr *CensysResponse

			log.Printf("Doing page %d of %d...\n", page, pageCount)

			cr, err = query.do(creds.Uid, creds.Secret, rhc)
			if err != nil {
				log.Print(err)
				page = page - 1
				time.Sleep(12)
				continue
			}

			if page == 1 {
				pageCount = cr.Metadata.Pages
			}
			log.Printf("Metadata: %+v\n", cr.Metadata)

			for _, rawCert := range cr.Results {
				cert, err := rawCert.ToX509()
				if err != nil {
					log.Printf("Error parsing certificate: %v\n", err)
					continue
				}

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
				if len(cert.DNSNames) > 0 {
					verifyOpts.DNSName = strings.Replace(cert.DNSNames[0], "*", "wildcard", 1)
				}
				chains, err := cert.Verify(verifyOpts)
				if err != nil {
					log.Print(err)
					log.Printf("SN: %v\n", cert.SerialNumber.Text(10))
					continue
				}
				logger.QueueChain(chains[0])
				wg.Add(1)
				go func() {
					defer wg.Done()
					logger.QueueChain(chains[0])
					return
					for _, chain := range chains {
						logger.QueueChain(chain)
					}
				}()
			}
			time.Sleep(6 * time.Second)
			//wg.Wait()
		}
	}

	logger.Wait()
	close(logerrchain)
}

func (q CensysQuery) do(uid, secret string, hc *retryablehttp.Client) (*CensysResponse, error) {

	queryJSON, err := json.Marshal(q)
	if err != nil {
		return nil, err
	}

	req, err := retryablehttp.NewRequest("POST", "https://censys.io/api/v1/search/certificates", bytes.NewReader(queryJSON))
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(uid, secret)

	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respJSON, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	parsed := &CensysResponse{}

	err = json.Unmarshal(respJSON, &parsed)
	if err != nil {
		return nil, err
	}

	return parsed, nil
}

func genIntermediatesPool(filename string) (*x509.CertPool, error) {
	intermediatesPEM, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	certpool := x509.NewCertPool()

	ok := certpool.AppendCertsFromPEM(intermediatesPEM)

	if !ok {
		return nil, fmt.Errorf("adding intermediates to intermediate pool failed?")
	}
	return certpool, nil
}
