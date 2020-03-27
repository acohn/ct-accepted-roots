package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/acohn/ct-accepted-roots/loglist"
	"github.com/gogo/protobuf/proto"
	pb_ts "github.com/golang/protobuf/ptypes/timestamp"
	"github.com/google/certificate-transparency-go/client/configpb"
)

var supportedShards = map[ShardedLogName]*regexp.Regexp{
	"nimbus": regexp.MustCompile(`^ct\.cloudflare\.com/logs/nimbus([0-9]{4})$`),
	"yeti":   regexp.MustCompile(`^yeti([0-9]{4})\.ct\.digicert\.com/log$`),
	"nessie": regexp.MustCompile(`^nessie([0-9]{4})\.ct\.digicert\.com/log$`),
	"argon":  regexp.MustCompile(`^ct\.googleapis\.com/logs/argon([0-9]{4})$`),
	"xenon":  regexp.MustCompile(`^ct\.googleapis\.com/logs/xenon([0-9]{4})$`),
	"solera": regexp.MustCompile(`^ct\.googleapis\.com/logs/solera([0-9]{4})$`),
	"oak":    regexp.MustCompile(`^oak\.ct\.letsencrypt\.org/([0-9]{4})$`),
	"360":    regexp.MustCompile(`^ct.browser.360.cn/([0-9]{4})$`),
}

type ShardedLogName string

func (s *ShardedLogName) String() string {
	return string(*s)
}

func (s *ShardedLogName) Set(name string) error {
	_, ok := supportedShards[ShardedLogName(name)]
	if ok {
		*s = ShardedLogName(name)
		return nil
	} else {
		return fmt.Errorf("Unknown shard name %s", name)
	}
}

type LogUrl string

func (u *LogUrl) String() string {
	return string(*u)
}
func (u *LogUrl) Set(log string) error {
	_, err := loglist.ByLogURL(log)
	if err != nil {
		return err
	}
	*u = LogUrl(log)
	return nil
}

var options = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

var shardedLog ShardedLogName
var fileName string
var prefixLog LogUrl
var postfixLog LogUrl

func init() {
	shardNames := make([]string, 0, len(supportedShards))
	for name := range supportedShards {
		shardNames = append(shardNames, string(name))
	}
	sort.Strings(shardNames)
	shards := strings.Join(shardNames, ", ")

	options.Var(&shardedLog, "l", "Name of `shard`ed log; one of "+shards)
	options.StringVar(&fileName, "o", "", "`file` to output log config to (default stdout)")
	options.Var(&prefixLog, "prefix", "non-sharded log `url` for certificates that expire before the earliest shard")
	options.Var(&postfixLog, "postfix", "non-sharded log `url` for certificates that expire after the last shard")
}

func main() {
	options.Parse(os.Args[1:])
	regex, ok := supportedShards[shardedLog]
	if !ok {
		options.Usage()
		os.Exit(1)
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

	if prefixLog != "" {
		prefix, err := loglist.ByLogURL(string(prefixLog))
		if err != nil {
			log.Fatalf("Couldn't find prefix log: %v", err)
		}

		prefixConfig := new(configpb.LogShardConfig)
		prefixConfig.Uri = "https://" + prefix.Url

		prefixConfig.PublicKeyDer, err = prefix.KeyDER()
		if err != nil {
			log.Fatal(err)
		}

		prefixConfig.NotAfterStart = nil
		prefixConfig.NotAfterLimit = config.Shard[0].NotAfterStart

		config.Shard = append([]*configpb.LogShardConfig{prefixConfig}, config.Shard...)
	}

	if postfixLog != "" {
		postfix, err := loglist.ByLogURL(string(postfixLog))
		if err != nil {
			log.Fatal(err)
		}
		postfixConfig := new(configpb.LogShardConfig)
		postfixConfig.Uri = "https://" + postfix.Url

		postfixConfig.PublicKeyDer, err = postfix.KeyDER()
		if err != nil {
			log.Fatal(err)
		}

		postfixConfig.NotAfterStart = config.Shard[len(config.Shard)-1].NotAfterLimit
		postfixConfig.NotAfterLimit = nil

		config.Shard = append(config.Shard, postfixConfig)
	}
	var output io.Writer
	if fileName != "" {
		var err error
		output, err = os.Create(fileName)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		output = os.Stdout
	}
	proto.MarshalText(output, config)
	if closer, ok := output.(io.Closer); ok {
		closer.Close()
	}
}
