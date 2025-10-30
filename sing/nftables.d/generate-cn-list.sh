#!/bin/sh

set -e

# 定义文件
CN_TXT="/etc/nftables.d/cn.txt"
CN_NFT="/etc/nftables.d/cn-list.nft"

echo "Downloading CN IP list..."
# 下载 cn.txt
wget -O "$CN_TXT" "https://ghfast.top/https://github.com/Loyalsoldier/geoip/raw/release/text/cn.txt"

echo "Generating NFT sets file..."
# 开始写 nft set 文件
{
echo "set cn_ipv4 {"
echo "    type ipv4_addr; flags interval; elements = {"
grep -v ":" "$CN_TXT" | awk '{ print "        " $1 "," }'
echo "    }"
echo "}"

echo ""

echo "set cn_ipv6 {"
echo "    type ipv6_addr; flags interval; elements = {"
grep ":" "$CN_TXT" | awk '{ print "        " $1 "," }'
echo "    }"
echo "}"
} > "$CN_NFT"

# 重新加载 nftables
nft -f /etc/nftables.d/sing-box.nft

echo "CN list updated and firewall rules reloaded."
