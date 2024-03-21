package main

import (
	"bufio"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

type Domain struct {
	Payload []string `yaml:"payload"`
}

func main() {

	_blocklist := []string{
		"pgdt.ugdtimg.com",
		"adsmind.ugdtimg.com",
	}

	dlerList := parseFromDler("https://github.com/dler-io/Rules/raw/main/Surge/Surge%203/Provider/Reject.list")
	genSurgeFile(dlerList, "reject.list")
	genClashFile(dlerList, "reject.yaml")
	genQuanXFile(dlerList, "reject.snippet")

	dnsFilter := parseFromAdguard("https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt")
	dnsFilter = append(dnsFilter, _blocklist...)
	genSurgeFile(dnsFilter, "dns_rej.list")
	genClashFile(dnsFilter, "dns_rej.yaml")
	genQuanXFile(dnsFilter, "dns_rej.snippet")
}

func parseFromAdguard(url string) []string {

	_list := []string{}
	res, _ := http.Get(url)

	if res.StatusCode != 200 {
		log.Fatal("reject http.Get() statusCode != 200")
		return _list
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(res.Body)

	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		l := scanner.Text()
		_l := ""
		re := regexp.MustCompile(`^\|\|\w+(\w|\.|\-)+\w+\^(\$important)?$`)
		if s := re.FindString(l); s != "" {
			rep := regexp.MustCompile(`^\|\|`)
			_l = rep.ReplaceAllString(s, "")
			res := regexp.MustCompile(`\^.*`)
			_l = res.ReplaceAllString(_l, "")
			_l = "." + strings.TrimSpace(_l)
		}

		if _l != "" && !slices.Contains(_list, _l) {
			_list = append(_list, _l)
		}
	}
	return _list
}

func parseFromDler(url string) []string {
	_list := []string{}

	res, _ := http.Get(url)

	if res.StatusCode != 200 {
		log.Fatal("reject http.Get() statusCode != 200")
		return _list
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(res.Body)

	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		l := scanner.Text()
		_l := ""

		re := regexp.MustCompile(`^DOMAIN-SUFFIX,(\w|\.|\-)+$`)
		if s := re.FindString(l); s != "" {
			re := regexp.MustCompile(`^DOMAIN-SUFFIX,`)
			_l = strings.TrimSpace(re.ReplaceAllString(s, ""))
			if l != "" {
				_l = "." + _l
			}
		}

		re2 := regexp.MustCompile(`^DOMAIN,(\w|\.|\-)+$`)
		if s := re2.FindString(l); s != "" {
			re := regexp.MustCompile(`^DOMAIN,`)
			_l = strings.TrimSpace(re.ReplaceAllString(s, ""))
		}

		if _l != "" && !slices.Contains(_list, _l) {
			_list = append(_list, _l)
		}
	}
	return _list
}

func genSurgeFile(domain []string, filename string) {
	_ = os.MkdirAll("./surge/list/", 0777)
	f, _ := os.Create("./surge/list/" + filename)

	for _, s := range domain {
		_, _ = f.WriteString(s + "\n")
	}

	defer closeFile(f)
}

func genClashFile(domain []string, filename string) {
	_ = os.MkdirAll("./clash/provider/", 0777)
	f, _ := os.Create("./clash/provider/" + filename)

	p := Domain{Payload: domain}
	out, _ := yaml.Marshal(&p)
	_ = os.WriteFile(f.Name(), out, 0777)

	defer closeFile(f)
}

func genQuanXFile(domain []string, filename string) {
	_ = os.MkdirAll("./quanx/list/", 0777)
	f, _ := os.Create("./quanx/list/" + filename)

	for _, s := range domain {
		if strings.HasPrefix(s, ".") {
			_, _ = f.WriteString("host-suffix, " + strings.TrimLeft(s, ".") + ", reject\n")
		} else {
			_, _ = f.WriteString("host, " + s + ", reject\n")
		}
	}

	defer closeFile(f)
}

func closeFile(f *os.File) {
	err := f.Close()
	if err != nil {
		log.Fatal(err)
	}
}
