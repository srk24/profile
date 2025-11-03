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
	"regexp"
	"sort"
	"strings"
	"sync"

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

	allow_block_domain_suffix := []string{
		"httpdns.bilivideo.com",
	}

	block_domain_suffix := []string{
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

	direct_domain := []string{
		"captive.apple.com",
		"time.apple.com",
		"api.github.com",
	}

	direct_domain_suffix := []string{
		"lcdn-locator.apple.com",
		"lcdn-registration.apple.com",
		"ls.apple.com",
		"steamserver.net",
		"steamcontent.com",
	}

	proxy_domain_suffix := []string{
		"alicesw.com",
		"uhdnow.com",
	}

	// 定义变量
	var err error
	var domain, domain_suffix, domain_keyword, domain_regex []string

	// 定义临时目录
	if err := os.MkdirAll("tmp", 0755); err != nil {
		log.Fatalf("Failed to create tmp directory: %v", err)
	}

	// 处理PCDN数据
	domain, domain_suffix, domain_keyword, domain_regex, err = parseSurgeFile("https://github.com/uselibrary/PCDN/raw/main/pcdn.list")
	if err == nil {
		release(domain, domain_suffix, domain_keyword, domain_regex, "pcdn")
	} else {
		log.Printf("Failed to parse PCDN list: %v", err)
	}

	// 处理AdGuard SDNS过滤器数据
	domain_suffix, err = parseAdGuardSDNSFilter("https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt")
	if err == nil {
		// 移除允许的域名
		cleaned_domain_suffix := make([]string, 0, len(domain_suffix))
		allowSet := make(map[string]struct{}, len(allow_block_domain_suffix))
		for _, s := range allow_block_domain_suffix {
			allowSet[s] = struct{}{}
		}
		for _, s := range domain_suffix {
			if _, ok := allowSet[s]; !ok {
				cleaned_domain_suffix = append(cleaned_domain_suffix, s)
			}
		}
		domain_suffix = cleaned_domain_suffix
		// 添加内置列表
		for _, item := range block_domain_suffix {
			domain_suffix = append(domain_suffix, item)
		}

		release(nil, domain_suffix, nil, nil, "adguard")
	} else {
		log.Printf("Failed to parse AdGuard SDNS filter list: %v", err)
	}

	// 处理AdRules数据
	domain, domain_suffix = parseClashDomainSetFile("https://github.com/Cats-Team/AdRules/raw/main/adrules_domainset.txt")
	if err == nil {
		// 添加内置列表
		for _, item := range block_domain_suffix {
			domain_suffix = append(domain_suffix, item)
		}
		release(domain, domain_suffix, domain_keyword, domain_regex, "adrules")
	} else {
		log.Printf("Failed to parse AdRules list: %v", err)
	}

	// 处理 v2ray 广告
	domain, domain_suffix, domain_keyword, domain_regex, err = parseSingboxSrs("https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-category-ads-all.srs")
	if err == nil {
		// 添加内置列表
		for _, item := range block_domain_suffix {
			domain_suffix = append(domain_suffix, item)
		}
		release(domain, domain_suffix, domain_keyword, domain_regex, "reject")
	} else {
		log.Printf("Failed to parse ads-all.srs: %v", err)
	}

	// 处理 v2ray 非中国地理位置数据
	domain, domain_suffix, domain_keyword, domain_regex, err = parseSingboxSrs("https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-geolocation-!cn.srs")
	if err == nil {
		// 添加内置列表
		for _, item := range proxy_domain_suffix {
			domain_suffix = append(domain_suffix, item)
		}
		release(domain, domain_suffix, domain_keyword, domain_regex, "geolocation-!cn")
	} else {
		log.Printf("Failed to parse ads-all.srs: %v", err)
	}

	// 处理 v2ray 中国地理位置数据
	domain, domain_suffix, domain_keyword, domain_regex, err = parseSingboxSrs("https://github.com/SagerNet/sing-geosite/raw/rule-set/geosite-geolocation-cn.srs")
	if err == nil {
		// 添加内置列表
		for _, item := range direct_domain {
			domain = append(domain, item)
		}
		for _, item := range direct_domain_suffix {
			domain_suffix = append(domain_suffix, item)
		}
		release(domain, domain_suffix, domain_keyword, domain_regex, "geolocation-cn")
	} else {
		log.Printf("Failed to parse ads-all.srs: %v", err)
	}

	// 清理临时目录
	defer os.RemoveAll("tmp")
}

// ======= parse various format files =======

func parseSurgeFile(fileUrl string) (domain, domain_suffix, domain_keyword, domain_regex []string, err error) {
	f, err := download(fileUrl)
	if err != nil {
		log.Printf("Failed to download surge file: %v", err)
		return
	}

	file, err := os.Open(f.Name())
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

func parseClashDomainSetFile(fileUrl string) (domain, domain_suffix []string) {
	f, err := download(fileUrl)
	if err != nil {
		log.Printf("Failed to download clash domain set file: %v", err)
		return
	}

	file, err := os.Open(f.Name())
	if err != nil {
		log.Printf("Failed to open file: %v", err)
		return
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
		return
	}
	return
}

func parseSingboxSrs(fileUrl string) (domain, domain_suffix, domain_keyword, domain_regex []string, err error) {
	f, err := download(fileUrl)
	if err != nil {
		log.Printf("Failed to download sing-geosite file: %v", err)
		return
	}

	var jsonFile string

	if strings.HasSuffix(fileUrl, ".srs") {
		err = decompileSingboxFile(f.Name())
		if err != nil {
			log.Printf("Failed to decompile sing-geosite file: %v", err)
			return
		}
		jsonFile = strings.TrimSuffix(f.Name(), filepath.Ext(f.Name())) + ".json"
	} else {
		jsonFile = f.Name()
	}

	var rules SingRuleSet
	byteValue, _ := os.ReadFile(jsonFile)
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

func parseAdGuardSDNSFilter(fileUrl string) (domainSuffix []string, err error) {
	var ignore_list []string

	f, err := download(fileUrl)
	if err != nil {
		log.Printf("Failed to download AdGuard SDNS filter file: %v", err)
		return
	}

	file, err := os.Open(f.Name())
	if err != nil {
		log.Printf("Failed to open file: %v", err)
		return
	}
	defer file.Close()

	// 匹配规则
	reWildcard := regexp.MustCompile(`^\|\|\*\.\s*([a-zA-Z0-9.-]+)\^?$`)
	reDomainSuffix := regexp.MustCompile(`^\|\|\s*([a-zA-Z0-9.-]+)\^?$`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" ||
			strings.HasPrefix(line, "!") || // 注释
			strings.HasPrefix(line, "@@") || // 例外
			strings.HasPrefix(line, "[Adblock") || // 元数据头
			strings.HasPrefix(line, "/") { // 正则过滤规则
			ignore_list = append(ignore_list, line)
			continue
		}

		switch {
		case reWildcard.MatchString(line):
			// 处理 ||*.example.com^
			m := reWildcard.FindStringSubmatch(line)
			domainSuffix = append(domainSuffix, m[1])
		case reDomainSuffix.MatchString(line):
			// 处理 ||example.com^
			m := reDomainSuffix.FindStringSubmatch(line)
			domainSuffix = append(domainSuffix, m[1])
		default:
			// 忽略其他类型（如 IP、脚本规则等）
			ignore_list = append(ignore_list, line)
			continue
		}
	}

	// 实现 排序 domain and domainSuffix
	sort.Strings(domainSuffix)

	// write ignore_list to file
	if len(ignore_list) > 0 {
		ignoreFilename := "adguard_ignore.list"
		log.Printf("Writing ignore list to file: %s", ignoreFilename)
		ignoreFile, err := os.Create(ignoreFilename)
		if err != nil {
			log.Printf("Failed to create ignore file: %v", err)
			return nil, err
		}
		defer ignoreFile.Close()

		writer := bufio.NewWriter(ignoreFile)
		for _, item := range ignore_list {
			if _, err := writer.WriteString(item + "\n"); err != nil {
				log.Printf("Failed to write to ignore file: %v", err)
				return nil, err
			}
		}
		writer.Flush()
	}
	return
}

// ======= release various format files =======

func release(domain, domain_suffix, domain_keyword, domain_regex []string, tag string) {
	log.Printf("Releasing tag: %s", tag)
	if len(domain) == 0 && len(domain_suffix) == 0 && len(domain_keyword) == 0 && len(domain_regex) == 0 {
		return
	}

	// 清理覆盖的域名
	domain, domain_suffix = cleanDomains(domain, domain_suffix)

	// 并行生成各种格式文件
	var wg sync.WaitGroup
	wg.Add(4)

	go func() {
		defer wg.Done()
		if err := releaseSurgeFile(tag, domain, domain_suffix); err != nil {
			log.Printf("Failed to generate surge file, tag: %v, err: %v", tag, err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := releaseClashFile(tag, domain, domain_suffix); err != nil {
			log.Printf("Failed to generate clash file, tag: %v, err: %v", tag, err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := releaseQuanXFile(tag, domain, domain_suffix, domain_keyword); err != nil {
			log.Printf("Failed to generate quanx file, tag: %v, err: %v", tag, err)
		}
	}()

	go func() {
		defer wg.Done()
		if err := releaseSingboxFile(tag, domain, domain_suffix, domain_regex, domain_keyword, nil); err != nil {
			log.Printf("Failed to generate singbox file, tag: %v, err: %v", tag, err)
		}
		filename := fmt.Sprintf("sing/ruleset/%s.json", tag)
		if err := compileSingboxFile(filename); err != nil {
			log.Printf("Failed to compile singbox file, tag: %v, err: %v", tag, err)
		}
	}()

	wg.Wait()
}

func releaseSurgeFile(tag string, domain, domainSuffix []string) error {
	filename := fmt.Sprintf("surge/list/%s.list", tag)
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

func releaseClashFile(tag string, domain, domainSuffix []string) error {
	filename := fmt.Sprintf("clash/provider/%s.yaml", tag)
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

func releaseQuanXFile(tag string, domain, domainSuffix, domainKeyword []string) error {
	filename := fmt.Sprintf("quanx/list/%s.snippet", tag)
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

func releaseSingboxFile(tag string, domain, domainSuffix, domainRegex, domainKeyword, processName []string) error {
	filename := fmt.Sprintf("sing/ruleset/%s.json", tag)
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

// ======= sing-box command =======

func compileSingboxFile(filename string) error {
	log.Printf("Compiling sing-box file: %s", filename)
	cmd := exec.Command("sing-box", "rule-set", "compile", filename)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("compile failed: %w", err)
	}
	return nil
}

func decompileSingboxFile(filename string) error {
	log.Printf("Decompiling sing-box file: %s", filename)
	cmd := exec.Command("sing-box", "rule-set", "decompile", filename)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("decompile failed: %w", err)
	}
	return nil
}

// ======= download =======

func download(downloadURL string) (*os.File, error) {
	if len(downloadURL) == 0 {
		return nil, fmt.Errorf("url is required")
	}

	// 发起HTTP GET请求
	log.Println("downloading", downloadURL)
	response, err := http.Get(downloadURL)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer response.Body.Close()

	// 检查HTTP响应状态码
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status error: %d %s", response.StatusCode, response.Status)
	}

	// 写入临时文件
	filename := filepath.Base(downloadURL)
	tempFile, err := os.CreateTemp("tmp", "*_"+filename)
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tempFile.Close()

	_, err = io.Copy(tempFile, response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to write to temp file: %w", err)
	}

	// 重置文件指针到开头
	if _, err := tempFile.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek temp file: %w", err)
	}

	return tempFile, nil
}

// ======= utils =======
// 清理覆盖的域名
func cleanDomains(domain, domainSuffix []string) ([]string, []string) {
	log.Printf("Cleaning domains: %d domains, %d suffixes", len(domain), len(domainSuffix))
	suffixSet := make(map[string]struct{}, len(domainSuffix))
	for _, s := range domainSuffix {
		suffixSet[s] = struct{}{}
	}

	cleanedDomain := make([]string, 0, len(domain))
	domainSeen := make(map[string]struct{}, len(domain))
	for _, d := range domain {
		if _, seen := domainSeen[d]; seen {
			continue
		}
		domainSeen[d] = struct{}{}

		covered := false
		for parent := parentDomain(d); parent != ""; parent = parentDomain(parent) {
			if _, ok := suffixSet[parent]; ok {
				covered = true
				break
			}
		}

		if !covered {
			cleanedDomain = append(cleanedDomain, d)
		}
	}

	cleanedSuffix := make([]string, 0, len(domainSuffix))
	suffixSeen := make(map[string]struct{}, len(domainSuffix))
	for _, s := range domainSuffix {
		if _, seen := suffixSeen[s]; seen {
			continue
		}

		covered := false
		for parent := parentDomain(s); parent != ""; parent = parentDomain(parent) {
			if _, ok := suffixSet[parent]; ok {
				covered = true
				break
			}
		}

		if !covered {
			cleanedSuffix = append(cleanedSuffix, s)
			suffixSeen[s] = struct{}{}
		}
	}

	return cleanedDomain, cleanedSuffix
}

func parentDomain(s string) string {
	if idx := strings.IndexByte(s, '.'); idx >= 0 && idx+1 < len(s) {
		return s[idx+1:]
	}
	return ""
}
