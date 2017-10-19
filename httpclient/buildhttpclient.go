package httpclient

import (
	"crypto/tls"
	"crypto/x509"
	"golang.org/x/net/http2"
	"net/http"
)

func Build() (*http.Client, error) {
	//Add the GDCA and CNNIC roots to the root store we use. Because they're using self-issued certs that aren't widely trusted.
	additionalCerts := []byte(`-----BEGIN CERTIFICATE-----
MIIFiDCCA3CgAwIBAgIIfQmX/vBH6nowDQYJKoZIhvcNAQELBQAwYjELMAkGA1UE
BhMCQ04xMjAwBgNVBAoMKUdVQU5HIERPTkcgQ0VSVElGSUNBVEUgQVVUSE9SSVRZ
IENPLixMVEQuMR8wHQYDVQQDDBZHRENBIFRydXN0QVVUSCBSNSBST09UMB4XDTE0
MTEyNjA1MTMxNVoXDTQwMTIzMTE1NTk1OVowYjELMAkGA1UEBhMCQ04xMjAwBgNV
BAoMKUdVQU5HIERPTkcgQ0VSVElGSUNBVEUgQVVUSE9SSVRZIENPLixMVEQuMR8w
HQYDVQQDDBZHRENBIFRydXN0QVVUSCBSNSBST09UMIICIjANBgkqhkiG9w0BAQEF
AAOCAg8AMIICCgKCAgEA2aMW8Mh0dHeb7zMNOwZ+Vfy1YI92hhJCfVZmPoiC7XJj
Dp6L3TQsAlFRwxn9WVSEyfFrs0yw6ehGXTjGoqcuEVe6ghWinI9tsJlKCvLriXBj
TnnEt1u9ol2x8kECK62pOqPseQrsXzrj/e+APK00mxqriCZ7VqKChh/rNYmDf1+u
KU49tm7srsHwJ5uu4/Ts765/94Y9cnrrpftZTqfrlYwiOXnhLQiPzLyRuEH3FMEj
qcOtmkVEs7LXLM3GKeJQEK5cy4KOFxg2fZfmiJqwTTQJ9Cy5WmYqsBebnh52nUpm
MUHfP/vFBu8btn4aRjb3ZGM74zkYI+dndRTVdVeSN72+ahsmUPI2JgaQxXABZG12
ZuGR224HwGGALrIuL4xwp9E7PLOR5G62xDtw8mySlwnNR30YwPO7ng/Wi64HtloP
zgsMR6flPri9fcebNaBhlzpBdRfMK5Z3KpIhHtmVdiBnaM8Nvd/WHwlqmuLMc3Gk
L30SgLdTMEZeS1SZD2fJpcjyIMGC7J0R38IC+xo70e0gmu9lZJIQDSri3nDxGGeC
jGHeuLzRL5z7D9Ar7Rt2ueQ5Vfj4oR24qoAATILnsn8JuLwwoC8N9VKejveSswoA
HQBUlwbgsQfZxw9cZX08bVlX5O2ljelAU58VS6Bx9hoh49pwBiFYFIeFd3mqgnkC
AwEAAaNCMEAwHQYDVR0OBBYEFOLJQJ9NzuiaoXzPDj9lxSmIahlRMA8GA1UdEwEB
/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4ICAQDRSVfg
p8xoWLoBDysZzY2wYUWsEe1jUGn4H3++Fo/9nesLqjJHdtJnJO29fDMylyrHBYZm
DRd9FBUb1Ov9H5r2XpdptxolpAqzkT9fNqyL7FeoPueBihhXOYV0GkLH6VsTX4/5
COmSdI31R9KrO9b7eGZONn356ZLpBN79SWP8bfsUcZNnL0dKt7n/HipzcEYwv1ry
L3ml4Y0M2fmyYzeMN2WFcGpcWwlyua1jPLHd+PwyvzeG5LuOmCd+uh8W4XAR8gPf
JWIyJyYYMoSf/wA6E7qaTfRPuBRwIrHKK5DOKcFw9C+df/KQHtZa37dG/OaG+svg
IHZ6uqbL9XzeYqWxi+7egmaKTjowHz+Ay60nugxe19CxVsp3cbK1daFQqUBDF8Io
2c9Si1vIY9RCPqAzekYu9wogRlR+ak8x8YF+QnQ4ZXMn7sZ8uI7XpTrXmKGcjBBV
09tL7ECQ8s1uV9JiDnxXk7Gnbc2dg7sq5+W2O3FYrf3RRbxake5TFW/TRQl1brqQ
XR4EzzffHqhmsYzmIGrv/EhOdJhCrylvLmrH+33RZjEizIYAfmaDDEL0vTSSwxrq
T8p+ck0LcIymSLumoRT2+1hEmRSuqguTaaApJUqlyyvdimYHFngVV3Eb7PVHhPOe
MTd61X8kreS8/f3MboPoDKi3QWwH3b08hpcv0g==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDVTCCAj2gAwIBAgIESTMAATANBgkqhkiG9w0BAQUFADAyMQswCQYDVQQGEwJD
TjEOMAwGA1UEChMFQ05OSUMxEzARBgNVBAMTCkNOTklDIFJPT1QwHhcNMDcwNDE2
MDcwOTE0WhcNMjcwNDE2MDcwOTE0WjAyMQswCQYDVQQGEwJDTjEOMAwGA1UEChMF
Q05OSUMxEzARBgNVBAMTCkNOTklDIFJPT1QwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDTNfc/c3et6FtzF8LRb+1VvG7q6KR5smzDo+/hn7E7SIX1mlwh
IhAsxYLO2uOabjfhhyzcuQxauohV3/2q2x8x6gHx3zkBwRP9SFIhxFXf2tizVHa6
dLG3fdfA6PZZxU3Iva0fFNrfWEQlMhkqx35+jq44sDB7R3IJMfAw28Mbdim7aXZO
V/kbZKKTVrdvmW7bCgScEeOAH8tjlBAKqeFkgjH5jCftppkA9nCTGPihNIaj3XrC
GHn2emU1z5DrvTOTn1OrczvmmzQgLx3vqR1jGqCA2wMv+SYahtKNu6m+UjqHZ0gN
v7Sg2Ca+I19zN38m5pIEo3/PIKe38zrKy5nLAgMBAAGjczBxMBEGCWCGSAGG+EIB
AQQEAwIABzAfBgNVHSMEGDAWgBRl8jGtKvf33VKWCscCwQ7vptU7ETAPBgNVHRMB
Af8EBTADAQH/MAsGA1UdDwQEAwIB/jAdBgNVHQ4EFgQUZfIxrSr3991SlgrHAsEO
76bVOxEwDQYJKoZIhvcNAQEFBQADggEBAEs17szkrr/Dbq2flTtLP1se31cpolnK
OOK5Gv+e5m4y3R6u6jW39ZORTtpC4cMXYFDy0VwmuYK36m3knITnA3kXr5g9lNvH
ugDnuL8BV8F3RTIMO/G0HAiw/VGgod2aHRM2mm23xzy54cXZF/qD1T0VoDy7Hgvi
yJA/qIYM/PmLXoXLT1tLYhFHxUV8BS9BsZ4QaRuZluBVeftOhpm4lNqGOGqTo+fL
buXf6iFViZx9fX+Y9QCJ7uOEwFyWtcVG6kbghVW2G8kS1sHNzYDzAgE8yGnLRUhj
2JTQ7IUOO04RZfSCjKY9ri4ilAnIXOo8gV0WKgOXFlUJ24pBgp5mmxE=
-----END CERTIFICATE-----
`)

	rootCerts, err := x509.SystemCertPool()
	if err != nil {
		if "crypto/x509: system root pool is not available on Windows" == err.Error() {
		// On Windows, you can't get the root store at runtime. Return a default client for now.
			return http.DefaultClient, nil
		} else {
			return nil, err
		}
	}

	rootCerts.AppendCertsFromPEM(additionalCerts)

	tlsConfig := &tls.Config{RootCAs: rootCerts}

	httpTransport := &http.Transport{TLSClientConfig: tlsConfig}

	//enable HTTP/2
	http2.ConfigureTransport(httpTransport)

	httpClient := &http.Client{Transport: httpTransport}
	return httpClient, nil
}
