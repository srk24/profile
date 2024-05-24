package main

import (
	"bufio"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

type Domain struct {
	Payload []string `yaml:"payload"`
}

type SingRuleSet struct {
	Version int        `json:"version,omitempty"`
	Rules   []SingRule `json:"rules,omitempty"`
}

type SingRule struct {
	Domain        []string `json:"domain,omitempty"`
	DomainSuffix  []string `json:"domain_suffix,omitempty"`
	DomainKeyword []string `json:"domain_keyword,omitempty"`
}

func main() {

	domain, domainSuffix, domainKeyword := parseFromSurgeRuleSet("https://github.com/dler-io/Rules/raw/main/Surge/Surge%203/Provider/Reject.list")
	genSurgeFile("reject.list", domain, domainSuffix)
	genClashFile("reject.yaml", domain, domainSuffix)
	genQuanXFile("reject.snippet", domain, domainSuffix, domainKeyword)
	genSingboxFile("reject.json", domain, domainSuffix, domainKeyword)
	genSingboxBinaryFile("reject.json")

	domain, domainSuffix = parseFromSurgeDomainSet("https://anti-ad.net/surge2.txt")
	genSingboxFile("anti_ad.json", domain, domainSuffix, nil)
	genSingboxBinaryFile("anti_ad.json")

	domain, domainSuffix, domainKeyword = parseFromSurgeRuleSet("https://ruleset.skk.moe/List/non_ip/apple_cdn.conf")
	genSingboxFile("apple_cdn.json", domain, domainSuffix, domainKeyword)
	genSingboxBinaryFile("apple_cdn.json")

	domain, domainSuffix, domainKeyword = parseFromSurgeRuleSet("https://ruleset.skk.moe/List/non_ip/microsoft_cdn.conf")
	genSingboxFile("microsoft_cdn.json", domain, domainSuffix, domainKeyword)
	genSingboxBinaryFile("microsoft_cdn.json")

	domain, domainSuffix, domainKeyword = parseFromSurgeRuleSet("https://ruleset.skk.moe/List/non_ip/stream.conf")
	genSingboxFile("stream.json", domain, domainSuffix, domainKeyword)
	genSingboxBinaryFile("stream.json")

	domain, domainSuffix, domainKeyword = parseFromSurgeRuleSet("https://ruleset.skk.moe/List/non_ip/global.conf")
	genSingboxFile("global.json", domain, domainSuffix, domainKeyword)
	genSingboxBinaryFile("global.json")

	domain, domainSuffix, domainKeyword = parseFromSurgeRuleSet("https://ruleset.skk.moe/List/non_ip/domestic.conf")
	genSingboxFile("domestic.json", domain, domainSuffix, domainKeyword)
	genSingboxBinaryFile("domestic.json")

	domain, domainSuffix, domainKeyword = parseFromSurgeRuleSet("https://ruleset.skk.moe/List/non_ip/apple_cn.conf")
	genSingboxFile("apple_cn.json", domain, domainSuffix, domainKeyword)
	genSingboxBinaryFile("apple_cn.json")

	genSingboxBinaryFile("process_cn.json")
}

func parseFromSurgeRuleSet(url string) (domain []string, domainSuffix []string, domainKeyword []string) {
	res, _ := http.Get(url)

	if res.StatusCode != 200 {
		log.Fatal("reject http.Get() statusCode != 200")
		return
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(res.Body)

	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		l := strings.ToLower(scanner.Text())
		if f := strings.HasPrefix(l, "domain,"); f {
			_l := strings.TrimSpace(strings.TrimPrefix(l, "domain,"))
			if _l != "" && !slices.Contains(domain, _l) {
				domain = append(domain, _l)
			}
			continue
		}
		if f := strings.HasPrefix(l, "domain-suffix,"); f {
			_l := strings.TrimSpace(strings.TrimPrefix(l, "domain-suffix,"))
			if _l != "" && !slices.Contains(domainSuffix, _l) {
				domainSuffix = append(domainSuffix, _l)
			}
			continue
		}
		if f := strings.HasPrefix(l, "domain-keyword,"); f {
			_l := strings.TrimSpace(strings.TrimPrefix(l, "domain-keyword,"))
			if _l != "" && !slices.Contains(domainKeyword, _l) {
				domainKeyword = append(domainKeyword, _l)
			}
			continue
		}
	}
	return domain, domainSuffix, domainKeyword
}

func parseFromSurgeDomainSet(url string) (domain []string, domainSuffix []string) {
	res, _ := http.Get(url)

	if res.StatusCode != 200 {
		log.Fatal("reject http.Get() statusCode != 200")
		return
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
		if f := strings.HasPrefix(l, "."); f {
			_l := strings.TrimSpace(strings.TrimPrefix(l, "."))
			if _l != "" && !slices.Contains(domainSuffix, _l) {
				domainSuffix = append(domainSuffix, _l)
			}
			continue
		}
		if f := strings.HasPrefix(l, "#"); !f {
			_l := strings.TrimSpace(l)
			if _l != "" && !slices.Contains(domain, _l) {
				domain = append(domain, _l)
			}
			continue
		}
	}
	return domain, domainSuffix
}

func genSurgeFile(filename string, domain []string, domainSuffix []string) {
	_ = os.MkdirAll("./surge/list/", 0777)
	f, _ := os.Create("./surge/list/" + filename)

	for _, s := range domain {
		_, _ = f.WriteString(s + "\n")
	}

	for _, s := range domainSuffix {
		_, _ = f.WriteString("." + s + "\n")
	}

	defer closeFile(f)
}

func genClashFile(filename string, domain []string, domainSuffix []string) {
	_ = os.MkdirAll("./clash/provider/", 0777)
	f, _ := os.Create("./clash/provider/" + filename)

	for _, s := range domainSuffix {
		_s := "." + s
		domain = append(domain, _s)
	}

	p := Domain{Payload: domain}
	out, _ := yaml.Marshal(&p)
	_ = os.WriteFile(f.Name(), out, 0777)

	defer closeFile(f)
}

func genQuanXFile(filename string, domain []string, domainSuffix []string, domainKeyword []string) {
	_ = os.MkdirAll("./quanx/list/", 0777)
	f, _ := os.Create("./quanx/list/" + filename)

	for _, s := range domain {
		_, _ = f.WriteString("host, " + s + ", direct\n")
	}

	for _, s := range domainSuffix {
		_, _ = f.WriteString("host-suffix, " + s + ", direct\n")
	}

	for _, s := range domainKeyword {
		_, _ = f.WriteString("host-keyword, " + s + ", direct\n")
	}

	defer closeFile(f)
}

func genSingboxFile(filename string, domain []string, domainSuffix []string, domainKeyword []string) {
	_ = os.MkdirAll("./sing/ruleset/", 0777)
	f, _ := os.Create("./sing/ruleset/" + filename)

	// singbox 1.8 support
	dodomainSuffix_1_8 := []string{}
	for _, s := range domainSuffix {
		dodomainSuffix_1_8 = append(dodomainSuffix_1_8, "."+s)
	}
	domainSuffix = dodomainSuffix_1_8

	rule := SingRule{
		Domain:        domain,
		DomainSuffix:  domainSuffix,
		DomainKeyword: domainKeyword,
	}
	data := SingRuleSet{
		Version: 1,
		Rules:   []SingRule{rule},
	}
	json, _ := json.Marshal(data)
	_, _ = f.Write(json)
	defer closeFile(f)
}

func genSingboxBinaryFile(filename string) {
	filename = "./sing/ruleset/" + filename
	re := regexp.MustCompile(`\.json`)
	_filename := strings.TrimSpace(re.ReplaceAllString(filename, ".srs"))

	if _, err := os.Stat(_filename); err == nil {
		err := os.Remove(_filename)
		if err != nil {
			log.Fatalf("remove file %s failed with %s\n", _filename, err)
		}
	}

	cmd := exec.Command("sing-box", "rule-set", "compile", "--output", _filename, filename)
	_err := cmd.Run()
	if _err != nil {
		log.Fatalf("cmd.Run() failed with %s\n", _err)
	}
}

func closeFile(f *os.File) {
	err := f.Close()
	if err != nil {
		log.Fatal(err)
	}
}
