# 准备工作

## openwrt pcocd

```bash
mv sing.init /etc/init.d/sing
```

## download or update to /opt/sing-box

[Releases Page](https://github.com/SagerNet/sing-box/releases/latest)

## 添加 oscp 流量直连

```bash
nft add table inet oscp_table
nft add chain inet oscp_table oscp_chain { type filter hook prerouting priority raw \; }
nft add rule inet oscp_table oscp_chain meta l4proto ip ip dscp 0x04 accept
nft add rule inet oscp_table oscp_chain meta l4proto ip6 ip6 dscp 0x04 accept
```
