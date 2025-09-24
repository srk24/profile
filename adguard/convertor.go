package adguard

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Rule represents a parsed AdGuard rule with its properties
type Rule struct {
	Content     string
	IsRawDomain bool
	IsExclude   bool
	IsSuffix    bool
	HasStart    bool
	HasEnd      bool
	IsRegexp    bool
	IsImportant bool
}

// Convert parses AdGuard rules from a reader and returns domain and exclude domain lists
func Convert(reader io.Reader) (domains, excludeDomains []string, err error) {
	scanner := bufio.NewScanner(reader)
	var rules []Rule
	var ignoredCount int

parseLoop:
	for scanner.Scan() {
		line := scanner.Text()
		
		// Skip comments and empty lines
		if line == "" || line[0] == '!' || line[0] == '#' {
			continue
		}
		
		originalLine := line
		
		// Check if line is already a domain name
		if isDomainName(line) {
			rules = append(rules, Rule{
				Content:     line,
				IsRawDomain: true,
			})
			continue
		}
		
		// Try parsing as a host line
		hostDomain, err := parseHostLine(line)
		if err == nil {
			if hostDomain != "" {
				rules = append(rules, Rule{
					Content:     hostDomain,
					IsRawDomain: true,
					HasStart:    true,
					HasEnd:      true,
				})
			}
			continue
		}
		
		// Remove trailing pipe if exists
		line = strings.TrimSuffix(line, "|")
		
		// Initialize rule properties
		var isExclude, isSuffix, hasStart, hasEnd, isRegexp, isImportant bool
		
		// Check for rule modifiers
		if !strings.HasPrefix(line, "/") && strings.Contains(line, "$") {
			params := strings.Split(strings.SplitN(line, "$", 2)[1], ",")
			line = strings.SplitN(line, "$", 2)[0]
			
			var skipRule bool
			for _, param := range params {
				paramParts := strings.SplitN(param, "=", 2)
				var handled bool
				
				if len(paramParts) > 0 && len(paramParts) <= 2 {
					switch paramParts[0] {
					case "important":
						handled = true
						isImportant = true
					case "dnsrewrite":
						if len(paramParts) == 2 && isUnspecifiedAddress(paramParts[1]) {
							handled = true
						}
					case "app", "network", "dnstype":
						// Not handling these modifiers
					}
				}
				
				if !handled {
					ignoredCount++
					fmt.Printf("Ignored unsupported rule with modifier %s: %s\n", paramParts[0], originalLine)
					skipRule = true
					break
				}
			}
			
			if skipRule {
				continue parseLoop
			}
		}
		
		// Check for exclusion rules
		if strings.HasPrefix(line, "@@") {
			line = line[2:]
			isExclude = true
		}
		
		// Remove trailing pipe again if exists
		line = strings.TrimSuffix(line, "|")
		
		// Check for domain suffix notation
		if strings.HasPrefix(line, "||") {
			line = line[2:]
			isSuffix = true
		} else if strings.HasPrefix(line, "|") {
			line = line[1:]
			hasStart = true
		}
		
		// Check for end of domain marker
		if strings.HasSuffix(line, "^") {
			line = line[:len(line)-1]
			hasEnd = true
		}
		
		// Check for regular expressions
		if strings.HasPrefix(line, "/") && strings.HasSuffix(line, "/") {
			line = line[1 : len(line)-1]
			if isIPCIDRRegexp(line) {
				ignoredCount++
				fmt.Printf("Ignored unsupported rule with IPCIDR regexp: %s\n", line)
				continue
			}
			isRegexp = true
		} else {
			// Handle URLs and paths
			if strings.Contains(line, "://") {
				line = strings.SplitN(line, "://", 2)[1]
			}
			
			if strings.Contains(line, "/") {
				ignoredCount++
				fmt.Printf("Ignored unsupported rule with path: %s\n", line)
				continue
			}
			
			if strings.Contains(line, "##") || strings.Contains(line, "#$#") {
				ignoredCount++
				fmt.Printf("Ignored unsupported rule with element hiding: %s\n", line)
				continue
			}
			
			// Validate domain
			domainCheck := line
			if strings.HasPrefix(domainCheck, ".") || strings.HasPrefix(domainCheck, "-") {
				domainCheck = "r" + domainCheck
			}
			
			if line == "" {
				ignoredCount++
				fmt.Printf("Ignored unsupported rule with empty domain: %s\n", originalLine)
				continue
			} else {
				domainCheck = strings.ReplaceAll(domainCheck, "*", "x")
				if !isDomainName(domainCheck) {
					_, ipErr := parseIPCIDRLine(line)
					if ipErr == nil {
						ignoredCount++
						fmt.Printf("Ignored unsupported rule with IPCIDR: %s\n", line)
						continue
					}
					
					if hasPort(domainCheck) {
						fmt.Printf("Ignored unsupported rule with port: %s\n", line)
					} else {
						fmt.Printf("Ignored unsupported rule with invalid domain: %s\n", line)
					}
					ignoredCount++
					continue
				}
			}
		}
		
		// Add rule to the list
		rules = append(rules, Rule{
			Content:     line,
			IsExclude:   isExclude,
			IsSuffix:    isSuffix,
			HasStart:    hasStart,
			HasEnd:      hasEnd,
			IsRegexp:    isRegexp,
			IsImportant: isImportant,
		})
	}
	
	// Check if we've got any valid rules
	if len(rules) == 0 {
		return nil, nil, fmt.Errorf("AdGuard rule-set is empty or all rules are unsupported")
	}
	
	// Check if all rules are raw domains
	if allRawDomains(rules) {
		return nil, nil, nil
	}
	
	// Process rules into domains and excluded domains
	var importantDomains, importantExcludeDomains, normalDomains, normalExcludeDomains []string
	
	for _, rule := range rules {
		if rule.IsRegexp {
			continue
		}
		
		formattedRule := formatRule(rule)
		
		if rule.IsImportant {
			if rule.IsExclude {
				importantExcludeDomains = append(importantExcludeDomains, formattedRule)
			} else {
				importantDomains = append(importantDomains, formattedRule)
			}
		} else {
			if rule.IsExclude {
				normalExcludeDomains = append(normalExcludeDomains, formattedRule)
			} else {
				normalDomains = append(normalDomains, formattedRule)
			}
		}
	}
	
	// Build final domain lists (important ones first)
	domains = extractCleanDomains(importantDomains)
	domains = append(domains, extractCleanDomains(normalDomains)...)
	
	excludeDomains = extractCleanDomains(importantExcludeDomains)
	excludeDomains = append(excludeDomains, extractCleanDomains(normalExcludeDomains)...)
	
	return domains, excludeDomains, nil
}

// Helper functions

func isDomainName(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	
	for _, part := range parts {
		if len(part) == 0 {
			return false
		}
		
		for i := 0; i < len(part); i++ {
			c := part[i]
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				return false
			}
		}
		
		if part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
	}
	
	// Check TLD is not all digits
	lastPart := parts[len(parts)-1]
	isAllDigits := true
	for i := 0; i < len(lastPart); i++ {
		if lastPart[i] < '0' || lastPart[i] > '9' {
			isAllDigits = false
			break
		}
	}
	
	return !isAllDigits
}

func hasPort(addr string) bool {
	return strings.Contains(addr, ":")
}

func isUnspecifiedAddress(addr string) bool {
	ip, err := netip.ParseAddr(addr)
	return err == nil && ip.IsUnspecified()
}

func parseHostLine(line string) (string, error) {
	idx := strings.Index(line, " ")
	if idx == -1 {
		return "", os.ErrInvalid
	}
	
	address, err := netip.ParseAddr(line[:idx])
	if err != nil {
		return "", err
	}
	
	if !address.IsUnspecified() {
		return "", nil
	}
	
	domain := line[idx+1:]
	if !isDomainName(domain) {
		return "", fmt.Errorf("invalid domain name: %s", domain)
	}
	
	return domain, nil
}

func parseIPCIDRLine(line string) (netip.Prefix, error) {
	var isPrefix bool
	if strings.HasSuffix(line, ".") {
		isPrefix = true
		line = line[:len(line)-1]
	}
	
	parts := strings.Split(line, ".")
	if (len(parts) > 4) || (len(parts) < 4 && !isPrefix) {
		return netip.Prefix{}, os.ErrInvalid
	}
	
	bytes := make([]byte, 0, len(parts))
	for _, part := range parts {
		val, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			return netip.Prefix{}, err
		}
		bytes = append(bytes, uint8(val))
	}
	
	bitLen := len(bytes) * 8
	for len(bytes) < 4 {
		bytes = append(bytes, 0)
	}
	
	var addr [4]byte
	copy(addr[:], bytes)
	return netip.PrefixFrom(netip.AddrFrom4(addr), bitLen), nil
}

func isIPCIDRRegexp(line string) bool {
	if strings.HasPrefix(line, "(http?:\\/\\/)") {
		line = line[12:]
	} else if strings.HasPrefix(line, "(https?:\\/\\/)") {
		line = line[13:]
	} else if strings.HasPrefix(line, "^") {
		line = line[1:]
	} else {
		return false
	}
	
	firstPart := strings.SplitN(line, "\\.", 2)[0]
	_, err := strconv.ParseUint(firstPart, 10, 8)
	return err == nil
}

func allRawDomains(rules []Rule) bool {
	for _, rule := range rules {
		if !rule.IsRawDomain {
			return false
		}
	}
	return true
}

func formatRule(rule Rule) string {
	result := rule.Content
	
	if rule.IsSuffix {
		result = "||" + result
	} else if rule.HasStart {
		result = "|" + result
	}
	
	if rule.HasEnd {
		result += "^"
	}
	
	return result
}

func extractCleanDomains(rules []string) []string {
	var result []string
	
	for _, rule := range rules {
		if !strings.Contains(rule, "*") {
			rule = strings.TrimLeft(rule, "|")
			rule = strings.TrimRight(rule, "^")
			result = append(result, rule)
		}
	}
	
	return result
}