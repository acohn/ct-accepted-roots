package get

import (
	"context"
	"crypto/x509"
	"github.com/acohn/ct-accepted-roots/loglist"
	"net/http"
)

func OneLog(ctx context.Context, hc *http.Client, ctLog loglist.Log) ([]*x509.Certificate, error) {
	cli, err := ctLog.Client(hc)
	if err != nil {
		return nil, err
	}
	acceptedRootDERs, err := cli.GetAcceptedRoots(ctx)
	if err != nil {
		return nil, err
	}

	var acceptedRoots []*x509.Certificate
	for _, acceptedRootDER := range acceptedRootDERs {
		if acceptedRoot, err := x509.ParseCertificate(acceptedRootDER.Data); err == nil {
			acceptedRoots = append(acceptedRoots, acceptedRoot) //ignore errors for now
		}
	}
	return acceptedRoots, nil
}
