package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

type _Options struct {
	Outbounds []option.Outbound `json:"outbounds,omitempty"`
}

type Config struct {
	Type     string `json:"type,omitempty"`
	Url      string `json:"url,omitempty"`
	Filename string `json:"filename,omitempty"`
}

var config = flag.String("c", "", "parser config file path")
var url = flag.String("i", "", "input singbox config url path")
var filename = flag.String("o", "./_outbounds.json", "output file path")

func main() {
	flag.Parse()

	var _config Config

	readConfig(&_config)

	vData, err := download(&_config.Url)
	if err != nil {
		log.Fatalf(err.Error())
	}
	outbounds, err := parse(vData, _config.Type)
	if err != nil {
		log.Fatalf(err.Error())
	}

	err = write(_config.Filename, outbounds)
	if err != nil {
		log.Fatalf(err.Error())
	}
}

func readConfig(_config *Config) {
	if len(*config) > 0 {
		c, _ := os.ReadFile(*config)
		if err := json.Unmarshal(c, &_config); err != nil {
			log.Fatalf(err.Error())
		}
	} else {
		_config = &Config{
			Url:      *url,
			Filename: *filename,
		}
	}
}

func download(downloadURL *string) ([]byte, error) {
	if len(*downloadURL) == 0 {
		log.Fatalf("url is required.")
	}
	log.Println("download ", *downloadURL)
	response, err := http.Get(*downloadURL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	return io.ReadAll(response.Body)
}

func parse(vOutboundDatas []byte, _dataType string) (outbounds []option.Outbound, err error) {
	var vOutbounds []option.Outbound
	switch _dataType {
	case "sing":
	default:
		if vOutbounds, err = parseSing(vOutboundDatas); err != nil {
			return nil, err
		}
	}

	var outbound_tags []string
	var ss_tags []string

	for _, v := range vOutbounds {
		if filterNode(&v) {
			outbounds = append(outbounds, v)
			outbound_tags = append(outbound_tags, v.Tag)
			if filterSS(&v) {
				ss_tags = append(ss_tags, v.Tag)
			}
		}
	}

	urltest := option.Outbound{
		Type: C.TypeURLTest,
		Tag:  "urltest",
		URLTestOptions: option.URLTestOutboundOptions{
			Outbounds:                 ss_tags,
			URL:                       "http://cp.cloudflare.com",
			Interval:                  option.Duration(1 * time.Minute),
			Tolerance:                 50,
			IdleTimeout:               option.Duration(30 * time.Minute),
			InterruptExistConnections: false,
		},
	}
	outbounds = append(outbounds, urltest)

	selector := option.Outbound{
		Type: C.TypeSelector,
		Tag:  "select-out",
		SelectorOptions: option.SelectorOutboundOptions{
			Outbounds:                 append([]string{"urltest"}, outbound_tags...),
			InterruptExistConnections: true,
		},
	}
	outbounds = append(outbounds, selector)

	return outbounds, err
}

func parseSing(vOutboundDatas []byte) ([]option.Outbound, error) {
	var options option.Options
	if err := options.UnmarshalJSON(vOutboundDatas); err != nil {
		return nil, err
	}
	return options.Outbounds, nil
}

func filterNode(h *option.Outbound) bool {
	switch h.Type {
	case C.TypeSOCKS, C.TypeHTTP, C.TypeShadowsocks, C.TypeVMess, C.TypeTrojan, C.TypeWireGuard, C.TypeHysteria, C.TypeTor, C.TypeSSH, C.TypeShadowTLS, C.TypeShadowsocksR, C.TypeVLESS, C.TypeTUIC, C.TypeHysteria2:
		return true
	default:
		return false
	}
}

func filterSS(h *option.Outbound) bool {
	switch h.Type {
	case C.TypeShadowsocks:
		return true
	default:
		return false
	}
}

func write(filename string, outbounds []option.Outbound) (err error) {
	options := _Options{
		Outbounds: outbounds,
	}
	jsonb, err := json.MarshalIndent(options, "", "\t")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(filename), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filename, jsonb, 0644); err != nil {
		return err
	}

	return nil
}
