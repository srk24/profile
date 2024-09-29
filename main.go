package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Payloads struct {
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
	DomainRegex   []string `json:"domain_regex,omitempty"`
	ProcessName   []string `json:"process_name,omitempty"`
	Invert        bool     `json:"invert,omitempty"`

	Type  string     `json:"type,omitempty"`
	Mode  string     `json:"mode,omitempty"`
	Rules []SingRule `json:"rules,omitempty"`
}

func main() {
	block_list := []string{
		"tanx.com",
		"miaozhen.com",
		"tqt.weibo.cn",
		"qzs.gdtimg.com",
		"gdt.qq.com",
		"open.e.kuaishou.cn",
		"open.e.kuaishou.com",
		"cnlogs.umeng.com",
		"umengcloud.com",
	}

	_ = os.MkdirAll("./sing/tmp/", 0777)

	CompileSingboxFile("./sing/ruleset/process_direct.json")

	f, _ := Download("https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", "./sing/ruleset/adguard.txt")
	ConvertSingboxFile(f.Name(), "adguard")
	os.Remove(f.Name())
	// DecompileSingboxFile("./sing/ruleset/adguard.srs")

	f, _ = Download("https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-category-ads-all.srs", "./sing/tmp/geosite-category-ads-all.srs")
	DecompileSingboxFile(f.Name())
	domain, domain_suffix, domain_keyword, _ := UnmarshalSingboxSourceCfg("./sing/tmp/geosite-category-ads-all.json")
	for _, item := range block_list {
		if exist := slices.Contains(domain_suffix, item); !exist {
			domain_suffix = append(domain_suffix, item)
		}
	}
	GenerateSurgeFile("./surge/list/reject.list", domain, domain_suffix)
	GenerateClashFile("./clash/provider/reject.yaml", domain, domain_suffix)
	GenerateQuanXFile("./quanx/list/reject.snippet", domain, domain_suffix, domain_keyword)

	f, _ = Download("https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-geolocation-!cn.srs", "./sing/tmp/geosite-geolocation-!cn.srs")
	DecompileSingboxFile(f.Name())
	domain, domain_suffix, domain_keyword, _ = UnmarshalSingboxSourceCfg("./sing/tmp/geosite-geolocation-!cn.json")
	GenerateSurgeFile("./surge/list/geolocation-!cn.list", domain, domain_suffix)
	GenerateClashFile("./clash/provider/geolocation-!cn.yaml", domain, domain_suffix)
	GenerateQuanXFile("./quanx/list/geolocation-!cn.snippet", domain, domain_suffix, domain_keyword)

	f, _ = Download("https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-geolocation-cn.srs", "./sing/tmp/geosite-geolocation-cn.srs")
	DecompileSingboxFile(f.Name())
	domain, domain_suffix, domain_keyword, _ = UnmarshalSingboxSourceCfg("./sing/tmp/geosite-geolocation-cn.json")
	GenerateSurgeFile("./surge/list/geolocation-cn.list", domain, domain_suffix)
	GenerateClashFile("./clash/provider/geolocation-cn.yaml", domain, domain_suffix)
	GenerateQuanXFile("./quanx/list/geolocation-cn.snippet", domain, domain_suffix, domain_keyword)

	defer os.RemoveAll("./sing/tmp/")
}

func UnmarshalSingboxSourceCfg(path string) (domain, domain_suffix, domain_keyword, domain_regex []string) {
	var rules SingRuleSet
	byteValue, _ := os.ReadFile(path)
	json.Unmarshal(byteValue, &rules)

	domain_map := make(map[string]bool)
	domain_suffix_map := make(map[string]bool)
	domain_keyword_map := make(map[string]bool)
	domain_regex_map := make(map[string]bool)
	for i := 0; i < len(rules.Rules); i++ {
		for _, item := range rules.Rules[i].Domain {
			if _, v := domain_map[item]; !v {
				domain_map[item] = true
				domain = append(domain, item)
			}
		}
		for _, item := range rules.Rules[i].DomainSuffix {
			if _, v := domain_suffix_map[item]; !v {
				domain_suffix_map[item] = true
				domain_suffix = append(domain_suffix, item)
			}
		}
		for _, item := range rules.Rules[i].DomainKeyword {
			if _, v := domain_keyword_map[item]; !v {
				domain_keyword_map[item] = true
				domain_keyword = append(domain_keyword, item)
			}
		}
		for _, item := range rules.Rules[i].DomainRegex {
			if _, v := domain_regex_map[item]; !v {
				domain_regex_map[item] = true
				domain_regex = append(domain_regex, item)
			}
		}
	}
	return
}

func GenerateSurgeFile(filename string, domain, domainSuffix []string) {
	f, _ := os.Create(filename)

	for _, s := range domain {
		_, _ = f.WriteString(s + "\n")
	}

	for _, s := range domainSuffix {
		_, _ = f.WriteString("." + s + "\n")
	}

	defer f.Close()
}

func GenerateClashFile(filename string, domain, domainSuffix []string) {
	f, _ := os.Create(filename)

	for _, s := range domainSuffix {
		_s := "." + s
		domain = append(domain, _s)
	}

	p := Payloads{Payload: domain}
	out, _ := yaml.Marshal(&p)
	_ = os.WriteFile(f.Name(), out, 0777)

	defer f.Close()
}

func GenerateQuanXFile(filename string, domain, domainSuffix, domainKeyword []string) {
	const d = ", direct\n"
	f, _ := os.Create(filename)

	for _, s := range domain {
		_, _ = f.WriteString("host, " + s + d)
	}

	for _, s := range domainSuffix {
		_, _ = f.WriteString("host-suffix, " + strings.TrimPrefix(s, ".") + d)
	}

	for _, s := range domainKeyword {
		_, _ = f.WriteString("host-keyword, " + s + d)
	}

	defer f.Close()
}

func GenerateSingboxFile(filename string, domain, domainSuffix, domainRegex, domainKeyword, processName []string) {
	f, _ := os.Create(filename)

	rule := SingRule{
		Domain:        domain,
		DomainSuffix:  domainSuffix,
		DomainRegex:   domainRegex,
		DomainKeyword: domainKeyword,
		ProcessName:   processName,
	}
	data := SingRuleSet{
		Version: 2,
		Rules:   []SingRule{rule},
	}
	json, _ := json.Marshal(data)
	_, _ = f.Write(json)
	f.Close()
}

func CompileSingboxFile(filename string) {
	cmd := exec.Command("sing-box", "rule-set", "compile", filename)
	err := cmd.Run()
	if err != nil {
		log.Fatalf("CompileSingboxFile failed with %s\n", err)
	}
}

func DecompileSingboxFile(filename string) {
	cmd := exec.Command("sing-box", "rule-set", "decompile", filename)
	err := cmd.Run()
	if err != nil {
		log.Fatalf("DecompileSingboxFile failed with %s\n", err)
	}
}

func ConvertSingboxFile(filename string, filetype string) {
	cmd := exec.Command("sing-box", "rule-set", "convert", filename, "-t", filetype)
	err := cmd.Run()
	if err != nil {
		log.Fatalf("ConvertSingboxFile failed with %s\n", err)
	}
}

func Download(downloadURL, output string) (*os.File, error) {
	if len(downloadURL) == 0 {
		log.Fatalf("url is required.")
	}

	log.Println("download", downloadURL)
	client := http.Client{
		Timeout: 5 * time.Second,
	}

	response, err := client.Get(downloadURL)
	if err != nil {
		return nil, err
	}

	f, _ := os.Create(output)
	_, err = io.Copy(f, response.Body)

	defer response.Body.Close()
	defer f.Close()

	return f, err
}
