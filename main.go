package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"profile/adguard"
	"slices"
	"strings"
	"sync"
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
		"adsmind.gdtimg.com",
		"gdt.qq.com",
		"e.kuaishou.cn",
		"e.kuaishou.com",
		"umeng.com",
		"umengcloud.com",
		"fapi.xdrun.com",
		"mix-mind.com",
		"in-neo.com",
		"rtbasia.com",
		"gridsum.com",
		"addnewer.com",
		"msmp.abchina.com.cn",
	}

	direct_list := []string{
		"api.github.com",
		"steamserver.net",
		"steamcontent.com",
		"dler.cloud",
		"dler.pro",
	}

	proxy_list := []string{
		"alicesw.com",
		"uhdnow.com",
	}

	if err := os.MkdirAll("./sing/tmp/", 0755); err != nil {
		log.Fatal("Failed to create directory: ", err)
	}

	// 处理进程数据
	processProcessData()

	// 处理PCDN数据
	processPCDN()

	// 处理AdGuard数据
	processAdGuard(block_list)

	// 处理AdRules数据
	processAdRules(block_list)

	// 处理 v2ray 广告和 HTTP DNS 数据
	processAdsData(block_list)

	// 处理 v2ray 非中国地理位置数据
	processNonCNGeositeData(proxy_list)

	// 处理 v2ray 中国地理位置数据
	processCNGeositeData(direct_list)

	// 清理临时目录
	defer os.RemoveAll("./sing/tmp/")
}

func processProcessData() {
	if err := CompileSingboxFile("./sing/ruleset/process_direct.json"); err != nil {
		log.Printf("Failed to compile process_direct.json: %v", err)
	}
}

func processPCDN() {
	f, err := Download("https://github.com/uselibrary/PCDN/raw/main/pcdn.list", "./sing/tmp/pcdn.list")
	if err != nil {
		log.Printf("Failed to download PCDN list: %v", err)
		return
	}

	domain, domain_suffix, domain_keyword, domain_regex := UnmarshalSurgeFile(f.Name())

	if err := GenerateSingboxFile("./sing/ruleset/pcdn.json", domain, domain_suffix, domain_regex, domain_keyword, nil); err != nil {
		log.Printf("Failed to generate singbox file: %v", err)
	}

	if err := CompileSingboxFile("./sing/ruleset/pcdn.json"); err != nil {
		log.Printf("Failed to compile singbox file: %v", err)
	}

	if err := GenerateSurgeFile("./surge/list/pcdn.list", domain, domain_suffix); err != nil {
		log.Printf("Failed to generate surge file: %v", err)
	}

	if err := GenerateQuanXFile("./quanx/list/pcdn.snippet", domain, domain_suffix, domain_keyword); err != nil {
		log.Printf("Failed to generate quanx file: %v", err)
	}
}

func processAdGuard(block_list []string) {
	f, err := Download("https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", "./sing/ruleset/adguard.txt")
	if err != nil {
		log.Printf("Failed to download AdGuard filter: %v", err)
		return
	}

	reader, err := os.Open("./sing/ruleset/adguard.txt")
	if err != nil {
		log.Printf("Failed to open AdGuard filter: %v", err)
		return
	}
	defer reader.Close()

	domain, excludeDomain, err := adguard.Convert(reader)
	if err == nil {
		if err := GenerateSurgeFile("./surge/list/adguard.list", domain, block_list); err != nil {
			log.Printf("Failed to generate adguard surge file: %v", err)
		}
		if err := GenerateSurgeFile("./surge/list/adguard_exclude.list", excludeDomain, nil); err != nil {
			log.Printf("Failed to generate adguard exclude surge file: %v", err)
		}
	} else {
		log.Printf("Failed to convert AdGuard filter: %v", err)
	}

	if err := ConvertSingboxFile(f.Name(), "adguard"); err != nil {
		log.Printf("Failed to convert AdGuard singbox file: %v", err)
	}

	if err := os.Remove(f.Name()); err != nil {
		log.Printf("Failed to remove temporary file: %v", err)
	}
}

func processAdsData(block_list []string) {
	sources := []string{
		"https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-category-ads-all.srs",
		// "https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-category-httpdns-cn@ads.srs",
	}

	jsonFiles := make([]string, len(sources))

	for i, src := range sources {
		output := filepath.Join("./sing/tmp", filepath.Base(src))
		f, err := Download(src, output)
		if err != nil {
			log.Printf("Failed to download %s: %v", src, err)
			continue
		}

		if err := DecompileSingboxFile(f.Name()); err != nil {
			log.Printf("Failed to decompile %s: %v", f.Name(), err)
			continue
		}

		jsonFile := strings.TrimSuffix(f.Name(), filepath.Ext(f.Name())) + ".json"
		jsonFiles[i] = jsonFile
	}

	domain, domain_suffix, domain_keyword, _ := UnmarshalSingboxSourceCfgMulti(jsonFiles)

	// 添加屏蔽列表
	for _, item := range block_list {
		if !slices.Contains(domain_suffix, item) {
			domain_suffix = append(domain_suffix, item)
		}
	}

	// 并行生成各种格式文件
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		if err := GenerateSurgeFile("./surge/list/reject.list", domain, domain_suffix); err != nil {
			log.Printf("Failed to generate reject surge file: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := GenerateClashFile("./clash/provider/reject.yaml", domain, domain_suffix); err != nil {
			log.Printf("Failed to generate reject clash file: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := GenerateQuanXFile("./quanx/list/reject.snippet", domain, domain_suffix, domain_keyword); err != nil {
			log.Printf("Failed to generate reject quanx file: %v", err)
		}
	}()

	wg.Wait()
}

func processAdRules(block_list []string) {
	src := "https://github.com/Cats-Team/AdRules/raw/main/adrules_domainset.txt"
	output := "./sing/tmp/adrules_domainset.txt"

	f, err := Download(src, output)
	if err != nil {
		log.Printf("Failed to download AdRules domain set: %v", err)
		return
	}

	domain, domain_suffix, err := UnmarshalClashDomainSetFile(f.Name())
	if err != nil {
		log.Printf("Failed to unmarshal AdRules domain set: %v", err)
		return
	}

	// 添加屏蔽列表
	for _, item := range block_list {
		if !slices.Contains(domain_suffix, item) {
			domain_suffix = append(domain_suffix, item)
		}
	}

	if err := GenerateSurgeFile("./surge/list/adrules.list", domain, domain_suffix); err != nil {
		log.Printf("Failed to generate adrules surge file: %v", err)
	}
}

func processNonCNGeositeData(proxy_list []string) {
	src := "https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-geolocation-!cn.srs"
	output := "./sing/tmp/geosite-geolocation-!cn.srs"

	f, err := Download(src, output)
	if err != nil {
		log.Printf("Failed to download non-CN geo data: %v", err)
		return
	}

	if err := DecompileSingboxFile(f.Name()); err != nil {
		log.Printf("Failed to decompile non-CN geo data: %v", err)
		return
	}

	domain, domain_suffix, domain_keyword, domain_regex := UnmarshalSingboxSourceCfg("./sing/tmp/geosite-geolocation-!cn.json")

	// 添加代理列表
	for _, item := range proxy_list {
		if !slices.Contains(domain, item) && !slices.Contains(domain_suffix, item) {
			domain_suffix = append(domain_suffix, item)
		}
	}

	// 并行生成各种格式文件
	var wg sync.WaitGroup
	wg.Add(4)

	go func() {
		defer wg.Done()
		if err := GenerateSurgeFile("./surge/list/geolocation-!cn.list", domain, domain_suffix); err != nil {
			log.Printf("Failed to generate non-CN surge file: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := GenerateSingboxFile("./sing/ruleset/geolocation-!cn.json", domain, domain_suffix, domain_regex, domain_keyword, nil); err != nil {
			log.Printf("Failed to generate singbox file: %v", err)
		}
		if err := CompileSingboxFile("./sing/ruleset/geolocation-!cn.json"); err != nil {
			log.Printf("Failed to compile singbox file: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := GenerateClashFile("./clash/provider/geolocation-!cn.yaml", domain, domain_suffix); err != nil {
			log.Printf("Failed to generate non-CN clash file: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := GenerateQuanXFile("./quanx/list/geolocation-!cn.snippet", domain, domain_suffix, domain_keyword); err != nil {
			log.Printf("Failed to generate non-CN quanx file: %v", err)
		}
	}()

	wg.Wait()
}

func processCNGeositeData(direct_list []string) {
	src := "https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-geolocation-cn.srs"
	output := "./sing/tmp/geosite-geolocation-cn.srs"

	f, err := Download(src, output)
	if err != nil {
		log.Printf("Failed to download CN geo data: %v", err)
		return
	}

	if err := DecompileSingboxFile(f.Name()); err != nil {
		log.Printf("Failed to decompile CN geo data: %v", err)
		return
	}

	domain, domain_suffix, domain_keyword, domain_regex := UnmarshalSingboxSourceCfg("./sing/tmp/geosite-geolocation-cn.json")

	// 添加直连列表
	for _, item := range direct_list {
		if !slices.Contains(domain, item) && !slices.Contains(domain_suffix, item) {
			domain_suffix = append(domain_suffix, item)
		}
	}

	// 并行生成各种格式文件
	var wg sync.WaitGroup
	wg.Add(4)

	go func() {
		defer wg.Done()
		if err := GenerateSurgeFile("./surge/list/geolocation-cn.list", domain, domain_suffix); err != nil {
			log.Printf("Failed to generate CN surge file: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := GenerateSingboxFile("./sing/ruleset/geolocation-cn.json", domain, domain_suffix, domain_regex, domain_keyword, nil); err != nil {
			log.Printf("Failed to generate singbox file: %v", err)
		}
		if err := CompileSingboxFile("./sing/ruleset/geolocation-cn.json"); err != nil {
			log.Printf("Failed to compile singbox file: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := GenerateClashFile("./clash/provider/geolocation-cn.yaml", domain, domain_suffix); err != nil {
			log.Printf("Failed to generate CN clash file: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := GenerateQuanXFile("./quanx/list/geolocation-cn.snippet", domain, domain_suffix, domain_keyword); err != nil {
			log.Printf("Failed to generate CN quanx file: %v", err)
		}
	}()

	wg.Wait()
}

func UnmarshalSingboxSourceCfgMulti(path []string) (domain, domain_suffix, domain_keyword, domain_regex []string) {
	for _, p := range path {
		_domain, _domain_suffix, _domain_keyword, _domain_regex := UnmarshalSingboxSourceCfg(p)
		domain = append(domain, _domain...)
		domain_suffix = append(domain_suffix, _domain_suffix...)
		domain_keyword = append(domain_keyword, _domain_keyword...)
		domain_regex = append(domain_regex, _domain_regex...)
	}
	return
}

func UnmarshalSingboxSourceCfg(path string) (domain, domain_suffix, domain_keyword, domain_regex []string) {
	var rules SingRuleSet
	byteValue, _ := os.ReadFile(path)
	json.Unmarshal(byteValue, &rules)

	domain_map := make(map[string]bool)
	domain_suffix_map := make(map[string]bool)
	domain_keyword_map := make(map[string]bool)
	domain_regex_map := make(map[string]bool)
	for _, rule := range rules.Rules {
		for _, item := range rule.Domain {
			if _, v := domain_map[item]; !v {
				domain_map[item] = true
				domain = append(domain, strings.TrimLeft(item, "."))
			}
		}
		for _, item := range rule.DomainSuffix {
			if _, v := domain_suffix_map[item]; !v {
				domain_suffix_map[item] = true
				domain_suffix = append(domain_suffix, strings.TrimLeft(item, "."))
			}
		}
		for _, item := range rule.DomainKeyword {
			if _, v := domain_keyword_map[item]; !v {
				domain_keyword_map[item] = true
				domain_keyword = append(domain_keyword, item)
			}
		}
		for _, item := range rule.DomainRegex {
			if _, v := domain_regex_map[item]; !v {
				domain_regex_map[item] = true
				domain_regex = append(domain_regex, item)
			}
		}
	}
	return
}

func UnmarshalSurgeFile(path string) (domain, domain_suffix, domain_keyword, domain_regex []string) {
	file, err := os.Open(path)
	if err != nil {
		log.Printf("Failed to open file: %v", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ",", 2)
		if len(parts) != 2 {
			log.Printf("Invalid line format: %s", line)
			continue
		}

		typ, value := strings.ToUpper(parts[0]), parts[1]
		switch typ {
		case "DOMAIN":
			domain = append(domain, value)
		case "DOMAIN-SUFFIX":
			domain_suffix = append(domain_suffix, value)
		case "DOMAIN-KEYWORD":
			domain_keyword = append(domain_keyword, value)
		case "DOMAIN-REGEX":
			domain_regex = append(domain_regex, value)
		default:
			log.Printf("Unknown rule type: %s", typ)
		}
	}
	return
}

func UnmarshalClashDomainSetFile(path string) (domain, domain_suffix []string, err error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	byteValue, _ := io.ReadAll(file)
	for line := range strings.SplitSeq(string(byteValue), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if trimmed, ok := strings.CutPrefix(line, "+."); ok {
			domain_suffix = append(domain_suffix, trimmed)
		} else {
			domain = append(domain, line)
		}
	}

	if len(domain) == 0 && len(domain_suffix) == 0 {
		return nil, nil, fmt.Errorf("no valid domain found")
	}

	return domain, domain_suffix, nil
}

func GenerateSurgeFile(filename string, domain, domainSuffix []string) error {
	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	writer := bufio.NewWriter(f)

	for _, s := range domain {
		if _, err := writer.WriteString(s + "\n"); err != nil {
			return fmt.Errorf("write error: %w", err)
		}
	}

	for _, s := range domainSuffix {
		if _, err := writer.WriteString("." + s + "\n"); err != nil {
			return fmt.Errorf("write error: %w", err)
		}
	}

	return writer.Flush()
}

func GenerateClashFile(filename string, domain, domainSuffix []string) error {
	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// 预分配适当大小的切片来减少重新分配
	combinedDomain := make([]string, len(domain), len(domain)+len(domainSuffix))
	copy(combinedDomain, domain)

	for _, s := range domainSuffix {
		combinedDomain = append(combinedDomain, "."+s)
	}

	p := Payloads{Payload: combinedDomain}
	out, err := yaml.Marshal(&p)
	if err != nil {
		return fmt.Errorf("yaml marshal error: %w", err)
	}

	return os.WriteFile(filename, out, 0644)
}

func GenerateQuanXFile(filename string, domain, domainSuffix, domainKeyword []string) error {
	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	const d = ", direct\n"
	writer := bufio.NewWriter(f)

	// 预估总容量以优化内存分配
	totalItems := len(domain) + len(domainSuffix) + len(domainKeyword)
	if totalItems > 1000 {
		writer = bufio.NewWriterSize(f, 65536) // 使用更大的缓冲区
	}

	for _, s := range domain {
		if _, err := writer.WriteString("host, " + s + d); err != nil {
			return fmt.Errorf("write error: %w", err)
		}
	}

	for _, s := range domainSuffix {
		if _, err := writer.WriteString("host-suffix, " + s + d); err != nil {
			return fmt.Errorf("write error: %w", err)
		}
	}

	for _, s := range domainKeyword {
		if _, err := writer.WriteString("host-keyword, " + s + d); err != nil {
			return fmt.Errorf("write error: %w", err)
		}
	}

	return writer.Flush()
}

func GenerateSingboxFile(filename string, domain, domainSuffix, domainRegex, domainKeyword, processName []string) error {
	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

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

	json, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("json marshal error: %w", err)
	}

	return os.WriteFile(filename, json, 0644)
}

func CompileSingboxFile(filename string) error {
	cmd := exec.Command("sing-box", "rule-set", "compile", filename)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("compile failed: %w", err)
	}
	return nil
}

func DecompileSingboxFile(filename string) error {
	cmd := exec.Command("sing-box", "rule-set", "decompile", filename)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("decompile failed: %w", err)
	}
	return nil
}

func ConvertSingboxFile(filename string, filetype string) error {
	cmd := exec.Command("sing-box", "rule-set", "convert", filename, "-t", filetype)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("convert failed: %w", err)
	}
	return nil
}

func Download(downloadURL, output string) (*os.File, error) {
	if len(downloadURL) == 0 {
		return nil, fmt.Errorf("url is required")
	}

	// 确保目录存在
	if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %w", err)
	}

	log.Println("downloading", downloadURL)
	client := http.Client{
		Timeout: 15 * time.Second, // 增加超时时间
		Transport: &http.Transport{
			MaxIdleConns:        10,
			IdleConnTimeout:     30 * time.Second,
			DisableCompression:  false,
			MaxIdleConnsPerHost: 5,
		},
	}

	response, err := client.Get(downloadURL)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status error: %d %s", response.StatusCode, response.Status)
	}

	f, err := os.Create(output)
	if err != nil {
		return nil, fmt.Errorf("failed to create file: %w", err)
	}

	// 使用bufio.Writer来提高写入性能
	writer := bufio.NewWriter(f)
	_, err = io.Copy(writer, response.Body)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to copy data: %w", err)
	}

	if err = writer.Flush(); err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to flush data: %w", err)
	}

	// 将文件指针重置到开始位置
	if _, err = f.Seek(0, 0); err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to seek to beginning: %w", err)
	}

	return f, nil
}
