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
	DomainRegex   []string `json:"domain_regex,omitempty"`
	ProcessName   []string `json:"process_name,omitempty"`
	Invert        bool     `json:"invert,omitempty"`

	Type  string     `json:"type,omitempty"`
	Mode  string     `json:"mode,omitempty"`
	Rules []SingRule `json:"rules,omitempty"`
}

func main() {
	existProcessName := []string{
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
	domain, domain_suffix := ParseDownloadFromV2fly("category-ads-all", "@ads")
	GenerateSurgeFile("category-ads-all.list", domain, domain_suffix)
	GenerateClashFile("category-ads-all.yaml", domain, domain_suffix)
	GenerateQuanXFile("category-ads-all.snippet", domain, domain_suffix, nil)
	log.Println("generate v2fly category-ads-all file down")

	domain, domain_suffix = ParseDownloadFromV2fly("geolocation-cn", "@cn")
	GenerateSurgeFile("geolocation-cn.list", domain, domain_suffix)
	GenerateClashFile("geolocation-cn.yaml", domain, domain_suffix)
	GenerateQuanXFile("geolocation-cn.snippet", domain, domain_suffix, nil)
	log.Println("generate v2fly geolocation-cn file down")

	domain, domain_suffix = ParseDownloadFromV2fly("geolocation-!cn", "@!cn")
	GenerateSurgeFile("geolocation-!cn.list", domain, domain_suffix)
	GenerateClashFile("geolocation-!cn.yaml", domain, domain_suffix)
	GenerateQuanXFile("geolocation-!cn.snippet", domain, domain_suffix, nil)
	log.Println("generate v2fly geolocation-!cn file down")

	domain, domain_suffix, domain_regex, allow_domain, allow_domain_suffix, allow_domain_regex := ParseDownloadAdGuardSDNSFilter("https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt")
	GenerateSurgeFile("adguard.list", domain, domain_suffix)
	GenerateClashFile("adguard.yaml", domain, domain_suffix)
	GenerateQuanXFile("adguard.snippet", domain, domain_suffix, nil)
	GenerateSingboxFileFromAdguard("adguard.json", domain, domain_suffix, domain_regex, allow_domain, allow_domain_suffix, allow_domain_regex)
	log.Println("generate adguard file down")

	domain, domain_suffix, domain_keyword, _ := ParseDownload("https://github.com/dler-io/Rules/raw/main/Surge/Surge%203/Provider/Reject.list")
	GenerateSurgeFile("reject.list", domain, domain_suffix)
	GenerateClashFile("reject.yaml", domain, domain_suffix)
	GenerateQuanXFile("reject.snippet", domain, domain_suffix, domain_keyword)
	GenerateSingboxFile("reject.json", domain, domain_suffix, domain_keyword, nil)
	log.Println("generate reject file down")

	domain, domain_suffix, domain_keyword, _ = ParseDownload("https://github.com/dler-io/Rules/raw/main/Surge/Surge%203/Provider/OpenAI.list")
	GenerateSurgeFile("llm.list", domain, domain_suffix)
	GenerateClashFile("llm.yaml", domain, domain_suffix)
	GenerateQuanXFile("llm.snippet", domain, domain_suffix, domain_keyword)
	GenerateSingboxFile("llm.json", domain, domain_suffix, domain_keyword, nil)
	log.Println("generate llm file down")

	_, _, _, process_name := ParseDownload("https://github.com/dler-io/Rules/raw/main/Clash/Provider/Special.yaml")
	for _, s := range existProcessName {
		if slices.Contains(existProcessName, s) {
			process_name = append(process_name, s)
		}
	}
	GenerateSingboxFile("process_direct.json", nil, nil, nil, process_name)
	log.Println("generate process_direct file down")

	domain, domain_suffix = ParseDownloadDomainset("https://anti-ad.net/surge2.txt")
	GenerateSingboxFile("anti_ad.json", domain, domain_suffix, nil, nil)
	log.Println("generate anti_ad file down")

}

func Download(downloadURL *string) ([]byte, error) {
	if len(*downloadURL) == 0 {
		log.Fatalf("url is required.")
	}
	// log.Println("download", *downloadURL)
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
		if f := len(s) == 0 || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";"); f {
			continue
		}
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

	return
}

func ParseDownloadDomainset(url string) (domain, domain_suffix []string) {
	vData, err := Download(&url)
	if err != nil {
		log.Fatalf(err.Error())
	}

	scanner := bufio.NewScanner(bytes.NewReader(vData))
	for scanner.Scan() {
		s := scanner.Text()
		if f := len(s) == 0 || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";"); f {
			continue
		}
		s = strings.TrimSpace(s)
		if strings.HasPrefix(s, ".") {
			domain_suffix = append(domain_suffix, strings.TrimPrefix(s, "."))
		} else if len(s) > 0 {
			domain = append(domain, s)
		}
	}

	return
}

func ParseDownloadAdGuardSDNSFilter(url string) (domain, domain_suffix, domain_regex, allow_domain, allow_domain_suffix, allow_domain_regex []string) {
	vData, err := Download(&url)
	if err != nil {
		log.Fatalf(err.Error())
	}

	prefixRe := regexp.MustCompile(`^(@@)?\|{0,2}`)
	suffixRe := regexp.MustCompile(`\^?\|?($important)?$`)

	// domain regex (no *)
	dr1 := regexp.MustCompile(`^\|{2}[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}[\^|]\|?($important)?$`)
	dr2 := regexp.MustCompile(`^\|[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}[\^|]\|?($important)?$`)

	// domain_regex regex (include *)
	rr1 := regexp.MustCompile(`(^\|{2}[a-zA-Z0-9.-]+\*+[a-zA-Z0-9.-]+[\^|]\|?($important)?$)|(^[a-zA-Z0-9.*-]+[\^|]\|?($important)?$)`) // 238
	rr2 := regexp.MustCompile(`^\|[a-zA-Z0-9.-]+\*+[a-zA-Z0-9.-]+[\^|]\|?($important)?$`)
	rr3 := regexp.MustCompile(`^\|{2}[a-zA-Z0-9.-]+\*+[a-zA-Z0-9.-]+$`)
	rr4 := regexp.MustCompile(`^\|[a-zA-Z0-9.-]+\*+[a-zA-Z0-9.-]+$`)

	// allow domain regex(no *)
	adr1 := regexp.MustCompile(`^@@\|{2}[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}[\^|]\|?($important)?$`)
	adr2 := regexp.MustCompile(`^@@\|[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}[\^|]\|?($important)?$`)

	// allow domain_regex regex (include *)
	arr1 := regexp.MustCompile(`(^@@\|{2}[a-zA-Z0-9.-]+\*+[a-zA-Z0-9.-]+[\^|]\|?($important)?$)|(^@@[a-zA-Z0-9.*-]+[\^|]\|?($important)?$)`)
	arr2 := regexp.MustCompile(`^@@\|[a-zA-Z0-9.-]+\*+[a-zA-Z0-9.-]+[\^|]\|?($important)?$`)

	scanner := bufio.NewScanner(bytes.NewReader(vData))
	for scanner.Scan() {
		s := strings.TrimSpace(scanner.Text())

		if f := len(s) == 0 || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "!") || strings.HasPrefix(s, ":") || strings.HasPrefix(s, "/"); f {
			continue
		}

		if f := dr1.MatchString(s); f {
			s = prefixRe.ReplaceAllString(s, "")
			s = suffixRe.ReplaceAllString(s, "")
			domain_suffix = append(domain_suffix, s)
			continue
		}

		if f := dr2.MatchString(s); f {
			s = prefixRe.ReplaceAllString(s, "")
			s = suffixRe.ReplaceAllString(s, "")
			domain = append(domain, s)
			continue
		}

		if f := rr1.MatchString(s); f {
			s = prefixRe.ReplaceAllString(s, "")
			s = suffixRe.ReplaceAllString(s, "")
			s = strings.ReplaceAll(s, ".", "\\.")
			s = strings.ReplaceAll(s, "*", ".*")
			s = ".*" + "\\." + s
			domain_regex = append(domain_regex, s)
			continue
		}

		if f := rr2.MatchString(s); f {
			s = prefixRe.ReplaceAllString(s, "")
			s = suffixRe.ReplaceAllString(s, "")
			s = strings.ReplaceAll(s, ".", "\\.")
			s = strings.ReplaceAll(s, "*", ".*")
			domain_regex = append(domain_regex, s)
			continue
		}

		if f := rr3.MatchString(s); f {
			s = prefixRe.ReplaceAllString(s, "")
			s = suffixRe.ReplaceAllString(s, "")
			s = strings.ReplaceAll(s, ".", "\\.")
			s = strings.ReplaceAll(s, "*", ".*")
			s = ".*" + "\\." + s + ".*"
			domain_regex = append(domain_regex, s)
			continue
		}

		if f := rr4.MatchString(s); f {
			s = prefixRe.ReplaceAllString(s, "")
			s = suffixRe.ReplaceAllString(s, "")
			s = strings.ReplaceAll(s, ".", "\\.")
			s = strings.ReplaceAll(s, "*", ".*")
			s = s + ".*"
			domain_regex = append(domain_regex, s)
			continue
		}

		if f := adr1.MatchString(s); f {
			s = prefixRe.ReplaceAllString(s, "")
			s = suffixRe.ReplaceAllString(s, "")
			allow_domain_suffix = append(allow_domain_suffix, s)
			continue
		}

		if f := adr2.MatchString(s); f {
			s = prefixRe.ReplaceAllString(s, "")
			s = suffixRe.ReplaceAllString(s, "")
			allow_domain = append(allow_domain, s)
			continue
		}

		if f := arr1.MatchString(s); f {
			s = prefixRe.ReplaceAllString(s, "")
			s = suffixRe.ReplaceAllString(s, "")
			s = strings.ReplaceAll(s, ".", "\\.")
			s = strings.ReplaceAll(s, "*", ".*")
			s = ".*" + "\\." + s
			allow_domain_regex = append(allow_domain_regex, s)
			continue
		}

		if f := arr2.MatchString(s); f {
			s = prefixRe.ReplaceAllString(s, "")
			s = suffixRe.ReplaceAllString(s, "")
			s = strings.ReplaceAll(s, ".", "\\.")
			s = strings.ReplaceAll(s, "*", ".*")
			allow_domain_regex = append(allow_domain_regex, s)
			continue
		}

		log.Printf("ignore adguard rule: %s", s)
	}

	return
}

// https://github.com/v2fly/domain-list-community/blob/master/data/category-ads-all
func ParseDownloadFromV2fly(name, suffix string) (domain, domain_suffix []string) {
	fp := "domain-list-community/data/" + strings.TrimSpace(name)
	file, err := os.Open(fp)
	if err != nil {
		log.Fatalf("failed to open file: %s", err)
	}
	defer file.Close()

	commentRe := regexp.MustCompile(`\s*#.*`)
	suffixRe := regexp.MustCompile(`\s*` + suffix)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		s := strings.TrimSpace(scanner.Text())

		if f := len(s) == 0 || strings.HasPrefix(s, "#"); f {
			continue
		}

		s = commentRe.ReplaceAllString(s, "")

		if f := strings.HasPrefix(s, "include:"); f {
			name := strings.TrimPrefix(s, "include:")
			_domain, _domain_suffix := ParseDownloadFromV2fly(name, suffix)
			domain = append(domain, _domain...)
			domain_suffix = append(domain_suffix, _domain_suffix...)
			continue
		}
		if f := strings.HasPrefix(s, "full:"); f {
			d := strings.TrimSpace(suffixRe.ReplaceAllString(strings.TrimPrefix(s, "full:"), ""))
			if strings.Contains(d, "@") {
				log.Printf("ignore v2fly rule= %s, file path=%s", s, fp)
				continue
			}
			domain = append(domain, d)
			continue
		}
		if f := strings.Contains(s, ":"); !f {
			ds := strings.TrimSpace(suffixRe.ReplaceAllString(s, ""))
			if strings.Contains(ds, "@") {
				log.Printf("ignore v2fly rule= %s, file path=%s", s, fp)
				continue
			}
			domain_suffix = append(domain_suffix, ds)
			continue
		}

		log.Printf("ignore v2fly rule= %s, file path=%s", s, fp)
	}

	return
}

func IsTLD(s string) bool {
	return strings.HasSuffix(s, ".com") || strings.HasSuffix(s, ".cn") || strings.HasSuffix(s, ".net") || strings.HasSuffix(s, ".info")
}

func GenerateSurgeFile(filename string, domain, domainSuffix []string) {
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

func GenerateClashFile(filename string, domain, domainSuffix []string) {
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

const QX_DEFAULT_RULE = ", direct\n"

func GenerateQuanXFile(filename string, domain, domainSuffix, domainKeyword []string) {
	_ = os.MkdirAll("./quanx/list/", 0777)
	f, _ := os.Create("./quanx/list/" + filename)

	for _, s := range domain {
		_, _ = f.WriteString("host, " + s + QX_DEFAULT_RULE)
	}

	for _, s := range domainSuffix {
		_, _ = f.WriteString("host-suffix, " + s + QX_DEFAULT_RULE)
	}

	for _, s := range domainKeyword {
		_, _ = f.WriteString("host-keyword, " + s + QX_DEFAULT_RULE)
	}

	defer closeFile(f)
}

func GenerateSingboxFile(filename string, domain, domainSuffix, domainKeyword, processName []string) {
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

func GenerateSingboxFileFromAdguard(filename string, domain, domainSuffix, domainRegex, allowDomain, allowDomainSuffix, allowDomainRegex []string) {
	_ = os.MkdirAll("./sing/ruleset/", 0777)
	f, _ := os.Create("./sing/ruleset/" + filename)

	rule := SingRule{
		Domain:       domain,
		DomainSuffix: domainSuffix,
		DomainRegex:  domainRegex,
	}

	allowRule := SingRule{
		Domain:       allowDomain,
		DomainSuffix: allowDomainSuffix,
		DomainRegex:  allowDomainRegex,
		Invert:       true,
	}

	logdicRule := SingRule{
		Type:  "logical",
		Mode:  "and",
		Rules: []SingRule{rule, allowRule},
	}

	data := SingRuleSet{
		Version: 1,
		Rules:   []SingRule{logdicRule},
	}
	json, _ := json.Marshal(data)
	_, _ = f.Write(json)
	closeFile(f)

	GenerateSingboxBinaryFile(filename)
}

func GenerateSingboxBinaryFile(filename string) {
	filename = "./sing/ruleset/" + filename
	re := regexp.MustCompile(`\.json`)
	f := strings.TrimSpace(re.ReplaceAllString(filename, ".srs"))

	if _, err := os.Stat(f); err == nil {
		err := os.Remove(f)
		if err != nil {
			log.Fatalf("remove file %s failed with %s\n", f, err)
		}
	}

	cmd := exec.Command("sing-box", "rule-set", "compile", "--output", f, filename)
	err := cmd.Run()
	if err != nil {
		log.Println("================")
		log.Fatalf("cmd.Run() failed with %s\n", err)
	}
}

func closeFile(f *os.File) {
	err := f.Close()
	if err != nil {
		log.Fatal(err)
	}
}
