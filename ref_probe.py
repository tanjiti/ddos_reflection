from __future__ import absolute_import
from __future__ import unicode_literals
from optparse import OptionParser
import select
import socket
import time
import sys
import json
import re
import subprocess
import logging

REF_PROBE_RULE = {
    'unknown': {  # 未知
        'service': 'unknown',
        'protocol': 'unknown',
    },
    'arms': {
        'service': 'arms',
        'protocol': 'net Assistant Apple Remote Desktop',
        'port_list': [
            3283,
        ],
        'payload_list': [
            '00140000',
        ],
        'ip_list': [
            '5.226.69.3'
        ],
    },
    'bacnet': {
        'service': 'bacnet',
        'protocol': 'Building Automation Control NETworks',
        'port_list': [
            478083,
        ],
        'payload_list': [

        ],
        'ip_list': [

        ],
    },
    'bfd': {
        'service': 'bfd',
        'protocol': 'Bidirectional Forwarding Detection (BFD)',
        'port_list': [
            3784,
        ],
        'payload_list': [
            '56c8f4f960a21ea54dfb03cc514ea11095afb26717678132fb57fd8ed2227203347abb98'
        ],
        'ip_list': [

        ],
    },
    'bittorrent': {
        'service': 'bittorrent',
        'protocol': 'bittorrent',
        'port_list': [
            6881,
        ],
        'payload_list': [
            "d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t1:a1:y1:qe",
        ],
        'ip_list': [

        ],
    },
    'chargen': {
        'service': 'chargen',
        'protocol': 'chargen',
        'port_list': [
            19,
        ],
        'payload_list': [
            "00",
        ],
        'ip_list': [

        ],
    },
    'citrix': {
        'service': 'citrix',
        'protocol': 'Citrix Legacy IMA Service (XenApp Servers',
        'port_list': [
            1604,
        ],
        'payload_list': [
            '2a00013202fda8e300000000000000000000000000000000000000000100020000000000000000000000',
        ],
        'ip_list': [

        ],
    },
    'cldap': {
        'service': 'cldap',
        'protocol': 'Citrix Legacy IMA Service (XenApp Servers',
        'port_list': [
            389,
        ],
        'payload_list': [
            '3025020101632004000a01000a0100020100020100010100870b6f626a656374636c6173733000',
        ],
        'ip_list': [
            '216.238.77.34',
        ],
    },
    'coap_over_gatt': {
        'service': 'coap_over_gatt',
        'protocol': 'coap_over_gatt',
        'port_list': [
            56666,
            57777,
        ],
        'payload_list': [
            '40010101bb2e77656c6c2d6b6e6f776e04636f7265',
        ],
        'ip_list': [
            '58.176.163.242',
        ],
    },
    'coap': {
        'service': 'coap',
        'protocol': 'coap',
        'port_list': [
            5683,
        ],
        'payload_list': [
            '40010101bb2e77656c6c2d6b6e6f776e04636f7265',
        ],
        'ip_list': [

        ],
    },
    'crestron': {
        'service': 'crestron',
        'protocol': 'Crestron 3-Series Control System',
        'port_list': [
            41794,
        ],
        'payload_list': [
            '14',
        ],
        'ip_list': [

        ],
    },
    'dhcpdiscover': {
        'service': 'dhcpdiscover',
        'protocol': 'DVR DHCPDiscover (multiple CCTV products) UDP-MIB',
        'port_list': [
            37810,
        ],
        'payload_list': [
            '44484950',
        ],
        'ip_list': [
            '98.190.136.25',
        ],
    },
    'dns': {
        'service': 'dns',
        'protocol': 'dns',
        'port_list': [
            53,
        ],
        'payload_list': [
            'cc170120000100000000000102736c0000ff0001000029ffff000000000000',
        ],
        'ip_list': [
            '84.22.46.54',
        ],
    },
    'dtls': {
        'service': 'dtls',
        'protocol': 'TLS over datagram transport',
        'port_list': [
            443,
        ],
        'payload_list': [
            '0a0000000000000000'
        ],
        'ip_list': [

        ],
    },
    'ipsec': {
        'service': 'ipsec',
        'protocol': 'ipsec',
        'port_list': [
            500,
        ],
        'payload_list': [
            '2100000000000000000000000000000001',
        ],
        'ip_list': [

        ],
    },
    'jenkins': {
        'service': 'jenkins',
        'protocol': 'Jenkins (Hudson Agent) CI Server Discovery CVE-2020-2100',
        'port_list': [
            33848,
        ],
        'payload_list': [
            '0a',
        ],
        'ip_list': [
            '85.214.104.48',
        ],
    },
    'lantronix': {
        'service': 'lantronix',
        'protocol': 'Lantronix Gateway Discovery',
        'port_list': [
            30718,

        ],
        'payload_list': [
            '000000f8',
        ],
        'ip_list': [

        ],
    },
    'memcache': {
        'service': 'memcache',
        'protocol': 'memcache',
        'port_list': [
            11211,
        ],
        'payload_list': [
            '000000000001000073746174730d0a',  # stats command
        ],
        'ip_list': [
            '5.39.93.111',
        ],
    },
    'modbus': {
        'service': 'modbus',
        'protocol': 'modbus',
        'port_list': [
            502,
            3074,
            44444,
            44445,
            44446,
        ],
        'payload_list': [
            "GET-REPORT-SVR-INFO"
        ],
        'ip_list': [

        ],
    },
    'mssql': {
        'service': 'mssql',
        'protocol': 'mssql',
        'port_list': [
            1434

        ],
        'payload_list': [
            '02',
        ],
        'ip_list': [
            '154.85.48.23'
        ],
    },
    'natpmp': {
        'service': 'natpmp',
        'protocol': 'NAT Port Mapping Protocol',
        'port_list': [
            5351,
        ],
        'payload_list': [
            '0000'
        ],
        'ip_list': [

        ],
    },
    'netbios': {
        'service': 'netbios',
        'protocol': 'netbios',
        'port_list': [
            137,
            138,
            139,
        ],
        'payload_list': [
            '80f00010000100000000000020434b41414141414141141414141414141414141414141414114141414141410000210001',
            'e5d80000000100000000000020434b4141414141414141414141414141414141414141414141414141414141410000210001',

        ],
        'ip_list': [

        ],
    },
    'netisrouters': {
        'service': 'netisrouters',
        'protocol': 'Netcore/Netis routers',
        'port_list': [
            53413
        ],
        'payload_list': [
            '0a',
        ],
        'ip_list': [

        ],
    },
    'ntp': {
        'service': 'ntp',
        'protocol': 'ntp',
        'port_list': [
            123,
        ],
        'payload_list': [
            "1700032a" + '00' * 44,
        ],
        'ip_list': [
            '183.213.30.129',
        ],
    },
    'openafs': {
        'service': 'openafs',
        'protocol': 'openafs',
        'port_list': [
            7001,

        ],
        'payload_list': [
            '000003e7000000000000006500000000000000000d0500000000000000',
        ],
        'ip_list': [

        ],
    },
    'openvpn': {
        'service': 'openvpn',
        'protocol': 'openvpn',
        'port_list': [
            1194,

        ],
        'payload_list': [
            '38',
        ],
        'ip_list': [

        ],
    },
    'phmgmt': {
        'service': 'phmgmt',
        'protocol': 'Powerhouse Management, Inc - VyprVPN and Outfox',
        'port_list': [
            20811
        ],
        'payload_list': [
            '00',

        ],
        'ip_list': [

        ],
    },
    'plex': {
        'service': 'plex',
        'protocol': 'plex/media-server',
        'port_list': [
            32414,
            32410,
        ],
        'payload_list': [
            'M-SEARCH * HTTP/1.1',

        ],
        'ip_list': [

        ],
    },
    'portmap': {
        'service': 'portmap',
        'protocol': 'portmap',
        'port_list': [
            111,

        ],
        'payload_list': [
            '65720a370000000000000002000186a0000000020000000400000000000000000000000000000000',
        ],
        'ip_list': [

        ],
    },
    'qotd': {
        'service': 'qotd',
        'protocol': 'Quote of the day',
        'port_list': [
            17,

        ],
        'payload_list': [
            '0d',

        ],
        'ip_list': [

        ],
    },
    'quake3': {
        'service': 'quake3',
        'protocol': 'quake3',
        'port_list': [
            27960,

        ],
        'payload_list': [
            'FFFFFFFF67657473746174757310',
        ],
        'ip_list': [

        ],
    },
    'quic': {
        'service': 'quic',
        'protocol': 'http3 encrypted multiplexed connections over UDP',
        'port_list': [
            443,
            80,

        ],
        'payload_list': [
            '0e0000000000000000',
        ],
        'ip_list': [

        ],
    },
    'rdp': {
        'service': 'rdp',
        'protocol': 'rdp',
        'port_list': [
            3389,
        ],
        'payload_list': [
            '00000000000000ff0000000000000000',
        ],
        'ip_list': [

        ],
    },
    'rip': {
        'service': 'rip',
        'protocol': 'routing information protocol',
        'port_list': [
            520,
        ],
        'payload_list': [

        ],
        'ip_list': [

        ],
    },
    'sadp': {
        'service': 'sadp',
        'protocol': 'Hikvision device discover via SADP over SSH',
        'port_list': [
            37020
        ],
        'payload_list': [
            '3c50726f62653e3c54797065733e696e71756972793c2f54797065733e3c2f50726f62653e',
        ],
        'ip_list': [
            '121.188.186.254',
        ],
    },
    'sentinel': {
        'service': 'sentinel',
        'protocol': 'sentinel',
        'port_list': [
            5093,
        ],
        'payload_list': [
            '7a0000000000',
        ],
        'ip_list': [

        ],
    },
    'sip': {
        'service': 'sip',
        'protocol': 'sip',
        'port_list': [
            5060
        ],
        'payload_list': [
            'aa',
        ],
        'ip_list': [

        ],
    },
    'snmp': {
        'service': 'snmp',
        'protocol': 'snmp',
        'port_list': [
            161
        ],
        'payload_list': [
            "302002010104067075626c6963a51302020001020100020146300730050601280500",
        ],
        'ip_list': [
            "68.171.218.123",
        ],
    },
    'srvloc': {
        'service': 'srvloc',
        'protocol': 'Service Location Protocol CVE-2023-29552',
        'port_list': [
            427,
        ],
        'payload_list': [
            '020900001d0000000000735f0002656e0000ffff000764656661756c74',
        ],
        'ip_list': [

        ],
    },
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
    'steam': {
        'service': 'steam',
        'protocol': 'a2s_info',
        'port_list': [
            2303,
        ],
        'payload_list': [
            b"\xFF\xFF\xFF\xFFSource Engine Query\x00",
        ],
        'ip_list': [

        ],
    },
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
    'tftp': {
        'service': 'tftp',
        'protocol': 'tftp',
        'port_list': [
            69,
        ],
        'payload_list': [

        ],
        'ip_list': [

        ],
    },
    'tp240': {
        'service': 'tp240',
        'protocol': 'TP240 Mitel Phone System',
        'port_list': [
            10074,
        ],
        'payload_list': [
            '63616c6c2e7374617274626c6173742032303030203300',
        ],
        'ip_list': [

        ],
    },
    'ubiquiti': {
        'service': 'ubiquiti',
        'protocol': 'ubiquiti',
        'port_list': [
            10001,
        ],
        'payload_list': [
            '01000000',
        ],
        'ip_list': [

        ],
    },
    'vxworks': {
        'service': 'vxworks',
        'protocol': 'vxWorks WDB ONCRPC (e.g. Motorola - Powerpc)',
        'port_list': [
            17185,
        ],
        'payload_list': [
            '1a09faba0000000000000002555555550000000100000001000000000000000000000000" \
                "00000000ffff55120000003c00000001000000020000000000000000',
        ],
        'ip_list': [

        ],
    },
    'wsdp': {
        'service': 'wsdp',
        'protocol': 'soap ws-discovery ONVIF',
        'port_list': [
            3702,
        ],
        'payload_list': [
            '<soap:Envelope><soap:Header>' \
            '<wsa:Action></wsa:Action>' \
            '<wsa:MessageID>urn:uuid:</wsa:MessagelD>' \
            '<wsa:To></wsa:To></soap:Header>' \
            '<soap:Body><tns:Probe/></soap:Body></soap:Envelope>',
        ],
        'ip_list': [

        ],
    },
    'xdmcp': {
        'service': 'xdmcp',
        'protocol': 'X Display Manager Control Protocol',
        'port_list': [
            177,
        ],
        'payload_list': [
            '00010002000100',
        ],
        'ip_list': [

        ],
    }
}


############# util ############
def is_hexstr(hexstr):
    """
    check hex string
    :param hexstr:
    :return:
    """
    ret = False
    if not hexstr:
        return ret
    hexstr = hexstr.lower()
    p = re.compile(r'^[0-9a-f]+$')
    m = re.match(p, hexstr)

    if m:
        ret = True

    return ret


def system_call(command, timeout=3600):
    """
    系统调用
    :param command:
    :param timeout:
    :return: stdout, stderr, process.returncode 0表示成功
    """
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return stdout, stderr, process.returncode
    except subprocess.TimeoutExpired:
        logging.error("[CMD_TIMEOUT]: %s %d" % (command, timeout))
    except Exception as e:
        logging.error("[UNKONWN_ERROR]: %s %s" % (command, str(e)))
    finally:
        process.stderr.close()
        process.stdout.close()
        while process.poll() is None:
            process.wait()


class RefProbeBase(object):
    """
    ref probe base
    """

    def __init__(self, **kwargs):
        """

        :param kwargs:
        """
        self.try_timeout = 2
        self.retry = 3
        self.timesleep = 1
        self.verbose = kwargs.get('verbose', False)
        self.ref_service = kwargs.get('ref_service')
        self.ref_port_list = kwargs.get('ref_port_list')
        self.ref_req_list = kwargs.get('ref_req_list')
        self.ref_server_list = kwargs.get('ref_server_list')

        self.bufsize = 65535
        self.dig_bin = '/usr/bin/dig'

    def probe_base(self, ref_server=None, ref_port=None, ref_req=None):
        """
        send ref request
        """

        if isinstance(ref_req, str):
            if is_hexstr(ref_req):
                ref_req = bytes.fromhex(ref_req)
            else:
                ref_req = ref_req.encode('utf-8')

        if not ref_req:
            return
        bytes_2send = len(ref_req)

        def send_payload(sock, ref_server=None, ref_port=None, ref_req=None):
            """
            send ref request
            """

            bytes_send = sock.sendto(ref_req, (ref_server, ref_port))
            if bytes_send == bytes_2send:
                if self.verbose:
                    print(ref_server, ref_port, ref_req, bytes_send)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', 0))

        send_payload(sock, ref_server, ref_port, ref_req)

        num_of_pkts = 0
        num_of_bytes = 0
        retry_time = 0
        ref_response_data = b''
        while True:
            rlist, wlist, xlist = select.select(
                [sock], [], [], self.try_timeout)
            if sock in rlist:
                data, addr = sock.recvfrom(self.bufsize)
                # udp payload bytes
                len_data = len(data) if data else 0
                #
                num_of_pkts += 1
                num_of_bytes += len_data
                if len_data > 0:
                    ref_response_data += data

            else:
                if num_of_bytes > 0:
                    break
                retry_time += 1
                if retry_time >= self.retry:
                    break
                # reset
                num_of_pkts = 0
                num_of_bytes = 0
                time.sleep(self.timesleep)
                send_payload(sock, ref_server, ref_port, ref_req)

        # BAF: bandwidth amplification factor
        # PAF: packet amplification factor
        result = {
            'ref_server': ref_server,
            'ref_port': ref_port,
            'ref_resp_pkts': num_of_pkts,
            'ref_resp_bytes': num_of_bytes,
            'ref_req_bytes': bytes_2send,
            'baf': round(num_of_bytes / bytes_2send, 2),
            'paf': num_of_pkts,

        }

        return result

    def probe(self, ref_server=None, ref_port=None, ref_req=None):
        """
        send ref request
        """

        if not ref_server and self.ref_server_list:
            ref_server = self.ref_server_list[0]
        if not ref_port and self.ref_port_list:
            ref_port = self.ref_port_list[0]
        if not ref_req and self.ref_req_list:
            ref_req = self.ref_req_list[0]

        if not ref_server:
            return
        if not ref_port:
            return
        if not ref_req:
            return

        result = self.probe_base(ref_server, ref_port, ref_req)
        if result:
            result['ref_service'] = self.ref_service
        return result

    def probe_with_dig(self, dns_server=None, domain='sl'):
        """
        dig @123.8.39.20  +tries=1 +nocookie +ignore +bufsize=65535 sl any

        """
        if not dns_server:
            dns_server = self.ref_server_list[0]
        p = r'MSG\s+SIZE\s+rcvd:\s+(\d+)'
        cmd = '{dig_bin} @{dns_server} +tries={try_times} +ignore +bufsize={bufsize}  {domain} any'.format(
            dns_server=dns_server,
            domain=domain,
            bufsize=self.bufsize,
            dig_bin=self.dig_bin,
            try_times=self.retry,
        )

        ret = system_call(cmd)
        response_size = 0
        if ret:
            stdout, stderr, retcode = ret
            if retcode == 0:
                if stdout:
                    stdout = stdout.decode('utf-8')

                    m = re.search(p, stdout, flags=re.DOTALL)
                    if m:
                        response_size = m.groups()[0]
                        response_size = int(response_size)

        bytes_2send = len(domain) + 71 - 42  # UDP header
        result = {
            'ref_server': dns_server,
            'ref_port': 53,
            'ref_resp_pkts': 1,
            'ref_resp_bytes': response_size,
            'ref_req_bytes': bytes_2send,
            'baf': round(response_size / bytes_2send, 2),
            'paf': 1,
        }
        return result


class RefProbe(RefProbeBase):
    """
    ssdp amplification_factor compute
    """

    def __init__(self, **kwargs):
        """

        :param kwargs:
        """
        RefProbeBase.__init__(self, **kwargs)

        self.ref_port_list = kwargs.get('port_list')
        self.ref_req_list = kwargs.get('payload_list')
        self.ref_service = kwargs.get('service')
        self.ref_server_list = kwargs.get('ip_list')


if __name__ == "__main__":
    """
    main
    """
    proto_tuple_list = ["%s(%s)" % (k, v.get('protocol')) for k, v in REF_PROBE_RULE.items()]
    support_ref_proto_list_str = ", ".join(proto_tuple_list)
    ref_proto_prompt = "support protocol({n}): {support_ref_proto_list_str}".format(
        support_ref_proto_list_str=support_ref_proto_list_str,
        n=len(proto_tuple_list)
    )

    parser = OptionParser()
    parser.add_option(
        "--proto", dest="proto",
        action="store", type="string",
        help="special reflection protocol, {ref_proto_prompt}".format(ref_proto_prompt=ref_proto_prompt)
    )
    parser.add_option(
        "--ip", dest="ip",
        action="store", type="string",
        help="special reflection ip",
    )
    parser.add_option(
        "--domain", dest="domain",
        action="store", type="string",
        help="special dns reflection domain, default sl",
        default='sl',
    )
    parser.add_option(
        "--port", dest="port",
        action="store", type="int",
        help="special reflection port",
    )
    parser.add_option(
        "--payload", dest="payload",
        action="store", type="string",
        help="special reflection payload hexstr",
    )
    parser.add_option(
        "--is_dig", dest='is_dig',
        action='store_true',
        help='dns reflection with dig ',
        default=False
    )
    (options, args) = parser.parse_args()

    ref_proto = options.proto
    ref_ip = options.ip
    ref_port = options.port
    ref_payload = options.payload
    dns_domain = options.domain
    is_dig = options.is_dig
    if ref_proto not in REF_PROBE_RULE:
        print("error: proto not support, {prompt}".format(prompt=ref_proto_prompt))
        sys.exit(1)
    proto_params = REF_PROBE_RULE.get(ref_proto)
    if not proto_params['service']:
        proto_params['service'] = ref_proto
        proto_params['protocol'] = ref_proto
    o = RefProbe(**proto_params)
    if ref_proto == 'unknown':
        if not (ref_ip and ref_port and ref_payload):
            print("error: need to specify the ip,port,payload for probing")
            sys.exit(1)
        else:
            result = o.probe(ref_server=ref_ip, ref_port=ref_port, ref_req=ref_payload)

    elif ref_proto == 'dns' and is_dig:
        result = o.probe_with_dig(dns_server=ref_ip, domain=dns_domain)
    else:
        result = o.probe(ref_server=ref_ip, ref_port=ref_port, ref_req=ref_payload)
    if result:
        print(json.dumps(result, indent=4))
