package main

import (
	"github.com/acohn/ct-accepted-roots/loglist"
	"github.com/gogo/protobuf/proto"
	pb_ts "github.com/golang/protobuf/ptypes/timestamp"
	"github.com/google/certificate-transparency-go/client/configpb"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"time"
)

func main() {
	var regex *regexp.Regexp
	if len(os.Args) < 2 {
		log.Fatal("Must specify name of sharded log to display, either argon, nimbus, or yeti")
	}
	switch logName := os.Args[1]; logName {
	case "nimbus":
		regex = regexp.MustCompile(`^ct\.cloudflare\.com/logs/nimbus([0-9]{4})$`)
	case "yeti":
		regex = regexp.MustCompile(`^yeti([0-9]{4})\.ct\.digicert\.com/log$`)
	case "argon":
		regex = regexp.MustCompile(`^ct\.googleapis\.com/logs/argon([0-9]{4})$`)
	default:
		log.Fatal("Unknown sharded log. Choose one of argon, nimbus, or yeti")
	}
	config := new(configpb.TemporalLogConfig)

	for _, ctlog := range loglist.Logs {
		if match := regex.FindStringSubmatch(ctlog.Url); match != nil {
			shard := new(configpb.LogShardConfig)
			shard.Uri = "https://" + ctlog.Url
			var err error
			shard.PublicKeyDer, err = ctlog.KeyDER()
			if err != nil {
				log.Fatal(err)
			}
			year, err := strconv.ParseInt(match[1], 10, 32)
			if err != nil {
				log.Fatal(err)
			}
			notAfterStart := time.Date(int(year), time.January, 1, 0, 0, 0, 0, time.UTC)
			shard.NotAfterStart = &pb_ts.Timestamp{Seconds: notAfterStart.Unix()}
			notAfterLimit := time.Date(int(year+1), time.January, 1, 0, 0, 0, 0, time.UTC)
			shard.NotAfterLimit = &pb_ts.Timestamp{Seconds: notAfterLimit.Unix()}
			config.Shard = append(config.Shard, shard)
		}
	}

	sort.Slice(config.Shard, func(i, j int) bool {
		return config.Shard[i].NotAfterStart.Seconds < config.Shard[j].NotAfterStart.Seconds
	})

	proto.MarshalText(os.Stdout, config)

}
