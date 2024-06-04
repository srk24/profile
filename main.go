package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
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
	ProcessName   []string `json:"process_name,omitempty"`
}

func main() {
	exist_process_name := []string{
		"storedownloadd",
		"v2ray",
		"ss-local",
		"UUBooster",
		"aria2c.exe",
		"BitComet.exe",
		"fdm.exe",
		"NetTransport.exe",
		"qbittorrent.exe",
		"Thunder.exe",
		"transmission-daemon.exe",
		"transmission-qt.exe",
		"uTorrent.exe",
		"WebTorrent.exe",
		"aria2c",
		"fdm",
		"Folx",
		"NetTransport",
		"qbittorrent",
		"qbittorrent-nox",
		"Thunder",
		"Transmission",
		"uTorrent",
		"WebTorrent",
		"WebTorrent Helper",
	}

	domain, domain_suffix, domain_keyword, _ := ParseDownload("https://github.com/dler-io/Rules/raw/main/Surge/Surge%203/Provider/Reject.list")
	GenerateSurgeFile("reject.list", domain, domain_suffix)
	GenerateClashFile("reject.yaml", domain, domain_suffix)
	GenerateQuanXFile("reject.snippet", domain, domain_suffix, domain_keyword)
	GenerateSingboxFile("reject.json", domain, domain_suffix, domain_keyword, nil)
	log.Println("generate file down")

	domain, domain_suffix, domain_keyword, _ = ParseDownload("https://github.com/dler-io/Rules/raw/main/Surge/Surge%203/Provider/OpenAI.list")
	GenerateSurgeFile("llm.list", domain, domain_suffix)
	GenerateClashFile("llm.yaml", domain, domain_suffix)
	GenerateQuanXFile("llm.snippet", domain, domain_suffix, domain_keyword)
	GenerateSingboxFile("llm.json", domain, domain_suffix, domain_keyword, nil)
	log.Println("generate file down")

	_, _, _, process_name := ParseDownload("https://github.com/dler-io/Rules/raw/main/Clash/Provider/Special.yaml")
	for _, s := range exist_process_name {
		if slices.Contains(exist_process_name, s) {
			process_name = append(process_name, s)
		}
	}
	GenerateSingboxFile("process_direct.json", nil, nil, nil, process_name)
	log.Println("generate file down")

	domain, domain_suffix = ParseDownloadDomainset("https://anti-ad.net/surge2.txt")
	GenerateSingboxFile("anti_ad.json", domain, domain_suffix, nil, nil)
	log.Println("generate file down")

}

func Download(downloadURL *string) ([]byte, error) {
	if len(*downloadURL) == 0 {
		log.Fatalf("url is required.")
	}
	log.Println("download", *downloadURL)
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	response, err := client.Get(*downloadURL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	return io.ReadAll(response.Body)
}

func ParseDownload(url string) (domain, domain_suffix, domain_keyword, process_name []string) {
	vData, err := Download(&url)
	if err != nil {
		log.Fatalf(err.Error())
	}

	scanner := bufio.NewScanner(bytes.NewReader(vData))
	for scanner.Scan() {
		s := strings.TrimSpace(scanner.Text())
		if f := strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";"); !f {
			sa := strings.Split(s, ",")
			if len(sa) > 1 {
				v := strings.TrimSpace(sa[1])
				switch strings.ToLower(strings.TrimSpace(sa[0])) {
				case "domain":
					domain = append(domain, v)
				case "domain-suffix":
					domain_suffix = append(domain_suffix, v)
				case "domain-keyword":
					domain_keyword = append(domain_keyword, v)
				case "process-name":
					process_name = append(process_name, v)
				}
			}
		}
	}

	return domain, domain_suffix, domain_keyword, process_name
}

func ParseDownloadDomainset(url string) (domain, domain_suffix []string) {
	vData, err := Download(&url)
	if err != nil {
		log.Fatalf(err.Error())
	}

	scanner := bufio.NewScanner(bytes.NewReader(vData))
	for scanner.Scan() {
		s := scanner.Text()
		if f := strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";"); !f {
			s = strings.TrimSpace(s)
			if strings.HasPrefix(s, ".") {
				domain_suffix = append(domain_suffix, strings.TrimPrefix(s, "."))
			} else if len(s) > 0 {
				domain = append(domain, s)
			}
		}
	}

	return domain, domain_suffix
}

func GetValue(s string, filter string) (data string) {
	if strings.Contains(strings.ToLower(s), strings.ToLower(filter)) {
		s = strings.TrimSpace(s)
		if f := strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";"); !f {
			sa := strings.Split(s, ",")
			if len(sa) > 1 && strings.EqualFold(strings.TrimSpace(sa[0]), filter) {
				data = strings.TrimSpace(sa[1])
			}
		}
	}
	return data
}

func GenerateSurgeFile(filename string, domain []string, domainSuffix []string) {
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

func GenerateClashFile(filename string, domain []string, domainSuffix []string) {
	_ = os.MkdirAll("./clash/provider/", 0777)
	f, _ := os.Create("./clash/provider/" + filename)

	for _, s := range domainSuffix {
		_s := "." + s
		domain = append(domain, _s)
	}

	p := Payloads{Payload: domain}
	out, _ := yaml.Marshal(&p)
	_ = os.WriteFile(f.Name(), out, 0777)

	defer closeFile(f)
}

func GenerateQuanXFile(filename string, domain []string, domainSuffix []string, domainKeyword []string) {
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

func GenerateSingboxFile(filename string, domain []string, domainSuffix []string, domainKeyword []string, processName []string) {
	_ = os.MkdirAll("./sing/ruleset/", 0777)
	f, _ := os.Create("./sing/ruleset/" + filename)

	rule := SingRule{
		Domain:        domain,
		DomainSuffix:  domainSuffix,
		DomainKeyword: domainKeyword,
		ProcessName:   processName,
	}
	data := SingRuleSet{
		Version: 1,
		Rules:   []SingRule{rule},
	}
	json, _ := json.Marshal(data)
	_, _ = f.Write(json)
	closeFile(f)

	GenerateSingboxBinaryFile(filename)
}

func GenerateSingboxBinaryFile(filename string) {
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
