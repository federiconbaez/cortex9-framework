#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# XDP vs nftables (netdev ingress) on the peer of a veth pair.
set -euo pipefail
export PATH="/usr/sbin:/sbin:/usr/bin:/bin:${PATH:-}"
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${BIN:-$ROOT/target/release/cortex9}
HOLD=${HOLD:-$ROOT/target/release/c9-xdp-hold}
POLICY=${POLICY:-$ROOT/policy/cortex9.toml}
OUT=${1:-/tmp/xdp-bench.json}
NS=c9ns$$; V0=c9a$$; V1=c9b$$; PIN=/sys/fs/bpf/cortex9
cleanup() {
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$V0" 2>/dev/null || true
}
trap cleanup EXIT
[[ $(id -u) -eq 0 ]] || { echo "FATAL: need root" >&2; exit 2; }

ip netns add "$NS"
ip link add "$V0" type veth peer name "$V1"
ip link set "$V1" netns "$NS"
ip addr add 10.67.0.1/24 dev "$V0"
ip netns exec "$NS" ip addr add 10.67.0.2/24 dev "$V1"
ip link set "$V0" up; ip netns exec "$NS" ip link set "$V1" up

TMP=$(mktemp -d)
cat > "$TMP/send.c" <<'C'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
static uint16_t csum(void *p, int len){uint32_t s=0;uint16_t*x=p;while(len>1){s+=*x++;len-=2;}if(len)s+=*(uint8_t*)x;while(s>>16)s=(s&0xffff)+(s>>16);return ~s;}
int main(int argc,char**argv){const char*iface=argv[1];int n=atoi(argv[2]);int mode=atoi(argv[3]);
 int fd=socket(AF_PACKET,SOCK_RAW,0);struct sockaddr_ll ll={0};ll.sll_family=AF_PACKET;ll.sll_ifindex=if_nametoindex(iface);ll.sll_halen=6;
 unsigned char pkt[64]={0};memset(pkt,0xff,6);pkt[6]=0x02;pkt[12]=0x08;pkt[13]=0x00;unsigned char*ip=pkt+14;ip[0]=0x45;ip[8]=64;ip[9]=17;
 unsigned tot=46;ip[2]=tot>>8;ip[3]=tot;inet_pton(AF_INET,mode==0?"203.0.113.7":"10.67.0.2",ip+12);inet_pton(AF_INET,"10.67.0.1",ip+16);
 uint16_t cs=csum(ip,20);ip[10]=cs>>8;ip[11]=cs;unsigned char*l4=pkt+34;l4[0]=0x9c;l4[1]=0x40;l4[2]=0xC9;l4[3]=0x09;l4[4]=0;l4[5]=26;
 for(int i=0;i<n;i++) sendto(fd,pkt,60,0,(struct sockaddr*)&ll,sizeof ll);return 0;}
C
cat > "$TMP/recv.c" <<'C'
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
int main(int argc,char**argv){int fd=socket(AF_PACKET,SOCK_RAW,htons(0x0800));struct sockaddr_ll ll={0};
 ll.sll_family=AF_PACKET;ll.sll_ifindex=if_nametoindex(argv[1]);ll.sll_protocol=htons(0x0800);bind(fd,(struct sockaddr*)&ll,sizeof ll);
 struct timeval tv={.tv_sec=atoi(argv[2])};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof tv);
 unsigned long n=0;unsigned char buf[2048];
 for(;;){ssize_t r=recv(fd,buf,sizeof buf,0);if(r<0)break;
  int off=14; if(r>=18 && ((buf[12]<<8|buf[13])==0x8100)) off=18;
  if(r<off+20+4) continue; if((buf[off]>>4)!=4) continue; int ihl=(buf[off]&0xf)*4;
  if(buf[off+9]!=17) continue; if(r<off+ihl+4) continue;
  unsigned dport=buf[off+ihl+2]<<8|buf[off+ihl+3]; if(dport!=0xC909) continue; n++;}
 printf("%lu\n",n);return 0;}
C
cc -O2 -o "$TMP/send" "$TMP/send.c"; cc -O2 -o "$TMP/recv" "$TMP/recv.c"
N=50000

ip netns exec "$NS" bash -c "
  nft add table netdev c9bench
  nft 'add chain netdev c9bench ingress { type filter hook ingress device \"$V1\" priority -100; policy accept; }'
  nft add rule netdev c9bench ingress ip saddr 203.0.113.0/24 drop
"
ip netns exec "$NS" "$TMP/recv" "$V1" 3 > "$TMP/nft.recv" &
RPID=$!; sleep 0.15
t0=$(date +%s.%N); "$TMP/send" "$V0" "$N" 0; t1=$(date +%s.%N)
wait "$RPID" || true
NFT_RECV=$(cat "$TMP/nft.recv"); NFT_DROP=$((N - NFT_RECV))
NFT_PPS=$(python3 -c "print(int($N / max($t1 - $t0, 1e-9)))")
ip netns exec "$NS" nft delete table netdev c9bench
echo "nftables: sent=$N recv=$NFT_RECV drop=$NFT_DROP pps=$NFT_PPS"

# Single netns process: mount bpffs, hold XDP, run measurements, write results.
ip netns exec "$NS" bash -c "
  set -e
  mount -t bpf -o mode=755 bpffs /sys/fs/bpf
  mkdir -p $PIN
  # Keep stdin open with a sleep so HOLD stays alive; kill by pid later.
  sleep 3600 | $HOLD $POLICY $PIN $V1 > $TMP/hold.log 2>&1 &
  HP=\$!
  for i in \$(seq 1 100); do grep -q READY $TMP/hold.log 2>/dev/null && break; sleep 0.05; done
  grep -q READY $TMP/hold.log

  $TMP/recv $V1 3 > $TMP/xdp.recv &
  RP=\$!; sleep 0.15
  # Tell host to send deny traffic
  echo deny > $TMP/phase
  wait \$RP || true
  $BIN xdp stats --pin-dir $PIN > $TMP/stats-deny

  $TMP/recv $V1 3 > $TMP/pass.recv &
  RP=\$!; sleep 0.15
  echo pass > $TMP/phase
  wait \$RP || true
  $BIN xdp stats --pin-dir $PIN > $TMP/stats-pass

  t0=\$(date +%s.%N)
  for i in \$(seq 1 100); do $BIN xdp reload --policy $POLICY --pin-dir $PIN >/dev/null; done
  t1=\$(date +%s.%N)
  python3 -c \"print(int((\$t1 - \$t0) * 1e6 / 100))\" > $TMP/reload_us

  kill \$HP 2>/dev/null || true
  echo done > $TMP/phase
" &
NSPID=$!

# Host sender driven by phase file.
for i in $(seq 1 200); do
  [[ -f $TMP/phase ]] && [[ $(cat $TMP/phase) == deny ]] && break
  sleep 0.05
done
[[ -f $TMP/phase ]] || { cat "$TMP/hold.log" 2>/dev/null; echo "FATAL: no phase" >&2; exit 1; }
t0=$(date +%s.%N); "$TMP/send" "$V0" "$N" 0; t1=$(date +%s.%N)
XDP_PPS=$(python3 -c "print(int($N / max($t1 - $t0, 1e-9)))")

for i in $(seq 1 200); do
  [[ $(cat $TMP/phase 2>/dev/null) == pass ]] && break
  sleep 0.05
done
t0=$(date +%s.%N); "$TMP/send" "$V0" "$N" 1; t1=$(date +%s.%N)
PASS_PPS=$(python3 -c "print(int($N / max($t1 - $t0, 1e-9)))")

wait "$NSPID"

XDP_RECV=$(cat "$TMP/xdp.recv")
PASS_RECV=$(cat "$TMP/pass.recv")
DROP_STAT=$(awk '/drop_deny_src/{print $1}' "$TMP/stats-deny"); DROP_STAT=${DROP_STAT:-0}
PASS_STAT=$(awk '/pass_default/{print $1}' "$TMP/stats-pass"); PASS_STAT=${PASS_STAT:-0}
RELOAD_US=$(cat "$TMP/reload_us")
echo "xdp-deny: sent=$N recv=$XDP_RECV drop_stat=$DROP_STAT pps=$XDP_PPS"
echo "xdp-pass: sent=$N recv=$PASS_RECV pass_stat=$PASS_STAT pps=$PASS_PPS"
echo "reload_avg_us=$RELOAD_US"

python3 - "$OUT" "$N" "$NFT_RECV" "$NFT_DROP" "$NFT_PPS" "$XDP_RECV" "$DROP_STAT" "$XDP_PPS" "$PASS_RECV" "$PASS_STAT" "$PASS_PPS" "$RELOAD_US" <<'PY'
import json, sys
(out,n,nft_recv,nft_drop,nft_pps,xdp_recv,xdp_drop,xdp_pps,pass_recv,pass_stat,pass_pps,reload_us)=sys.argv[1:13]
n=int(n); xdp_drop=int(xdp_drop); xdp_recv=int(xdp_recv); pass_recv=int(pass_recv)
xdp_eff = xdp_drop if xdp_drop else max(0, n - xdp_recv)
doc={
 "pillar":"xdp","frames_per_case":n,"attach":"peer_netdev_ingress_skb",
 "nftables":{"recv":int(nft_recv),"drop":int(nft_drop),"drop_rate":max(0,int(nft_drop))/n,"sender_pps":int(nft_pps)},
 "xdp_deny_src":{"recv":xdp_recv,"drop_stat":xdp_drop,"drop_rate":xdp_eff/n,"sender_pps":int(xdp_pps)},
 "xdp_pass":{"recv":pass_recv,"pass_stat":int(pass_stat),"pass_rate":pass_recv/n,"sender_pps":int(pass_pps)},
 "reload_avg_us":int(reload_us),
 "note":"Both on peer (V1) ingress; sender on V0; recv filters UDP dport 0xC909",
}
json.dump(doc, open(out,"w"), indent=2); print(open(out).read())
assert int(nft_drop) >= n*0.99, ("nft", doc)
assert xdp_eff >= n*0.99, ("xdp-deny", doc)
assert pass_recv >= n*0.90, ("xdp-pass", doc)
PY
