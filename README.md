# 简介

本项目的配置适用于 [**Clash Premium**](https://github.com/Dreamacro/clash/releases/tag/premium)、 [**Surge**](https://nssurge.com/)、 [**Quanmutumlt X**](https://apps.apple.com/us/app/quantumult-x/id1443988620)

## 说明

本项目中规则集的数据是每天定时拉取 dler-io/Rules 项目内容重新生成

### Clash Rule Providers 配置方式

```yaml
rule-providers:
  dns_rej:
    type: http
    behavior: domain
    url: https://github.com/srk24/profile/raw/master/clash/provider/dns_rej.yaml
    path: ./ruleset/dns_rej.yaml
    interval: 86400
```

### Surge Domain-set 配置方式

```text
DOMAIN-SET,https://github.com/srk24/profile/raw/master/surge/list/dns_rej.list,REJECT-TINYGIF,extended-matching
```

### Quan X 配置方式

```text
[filter_remote]
https://github.com/srk24/profile/raw/master/quanx/list/dns_rej.snippet, tag=dns_rej, update-interval=172800, opt-parser=false, inserted-resource=true, enabled=true
```

## 致谢

- [@app2smile/rules](https://github.com/app2smile/rules)
- [@blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)
- [@dler-io/Rules](https://github.com/dler-io/Rules)
- [@DivineEngine/Profiles](https://github.com/DivineEngine/Profiles)
- [@yichahucha/surge](https://github.com/yichahucha/surge)
- [@yjqiang/surge_scripts](https://github.com/yjqiang/surge_scripts)
- [@zmqcherish/proxy-script](https://github.com/zmqcherish/proxy-script)

## License

This software is released under the MIT license.

[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fsrk24%2Fprofile.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fsrk24%2Fprofile?ref=badge_large)
