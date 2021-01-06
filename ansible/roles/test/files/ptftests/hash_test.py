'''
Description:    This file contains the hash test for SONiC
'''

#---------------------------------------------------------------------
# Global imports
#---------------------------------------------------------------------
import logging
import random
import json
import time

from ipaddress import ip_address, ip_network

import ptf
import ptf.packet as scapy

from ptf.base_tests import BaseTest
from ptf.mask import Mask
from ptf.testutils import test_params_get
from ptf.testutils import simple_tcp_packet
from ptf.testutils import simple_tcpv6_packet
from ptf.testutils import send_packet
from ptf.testutils import verify_packet_any_port

import fib
import lpm

class HashTest(BaseTest):

    #---------------------------------------------------------------------
    # Class variables
    #---------------------------------------------------------------------
    DEFAULT_BALANCING_RANGE = 0.25
    BALANCING_TEST_TIMES = 625

    _required_params = [
        'setup_info',
        'ptf_port_dut_map'
    ]

    def __init__(self):
        '''
        @summary: constructor
        '''
        BaseTest.__init__(self)
        self.test_params = test_params_get()
        self.check_required_params()

    def check_required_params(self):
        for param in self._required_params:
            if param not in self.test_params:
                raise Exception("Missing required parameter {}".format(param))

    def setUp(self):
        '''
        @summary: Setup for the test
        '''
        self.dataplane = ptf.dataplane_instance

        setup_info = self.test_params.get('setup_info')
        with open(setup_info) as f:
            self.setup_info = json.load(f)

        self.fibs = []
        for fib_info_file in self.setup_info['fib_info_files']:
            self.fibs.append(fib.Fib(fib_info_file))

        ptf_port_dut_map = self.test_params.get('ptf_port_dut_map')
        with open(ptf_port_dut_map) as f:
            self.ptf_port_dut_map = json.load(f)

        self.src_ip_range = [unicode(x) for x in self.test_params['src_ip_range'].split(',')]
        self.dst_ip_range = [unicode(x) for x in self.test_params['dst_ip_range'].split(',')]
        self.src_ip_interval = lpm.LpmDict.IpInterval(ip_address(self.src_ip_range[0]), ip_address(self.src_ip_range[1]))
        self.dst_ip_interval = lpm.LpmDict.IpInterval(ip_address(self.dst_ip_range[0]), ip_address(self.dst_ip_range[1]))
        self.vlan_ids = self.test_params.get('vlan_ids', [])
        self.hash_keys = self.test_params.get('hash_keys', ['src-ip', 'dst-ip', 'src-port', 'dst-port'])

        self.balancing_range = self.test_params.get('balancing_range', self.DEFAULT_BALANCING_RANGE)
        self.balancing_test_times = self.test_params.get('balancing_test_times', self.BALANCING_TEST_TIMES)

    def get_src_and_exp_ports(self, dut_index, dst_ip):
        while True:
            src_port = int(random.choice(self.setup_info['duts_ptf_ports'][str(dut_index)]))
            ptf_port_active_dut_index = self.ptf_port_dut_map[str(src_port)][0]
            next_hop = self.fibs[ptf_port_active_dut_index][dst_ip]
            exp_port_list = next_hop.get_next_hop_list()
            if src_port in exp_port_list:
                continue
            break
        return src_port, exp_port_list, next_hop

    def check_hash(self, hash_key):
        for dut_index, fib in enumerate(self.fibs):
            dst_ip = self.dst_ip_interval.get_random_ip()
            src_port, exp_port_list, next_hop = self.get_src_and_exp_ports(dut_index, dst_ip)
            logging.info("dst_ip={}, src_port={}, exp_port_list={}".format(dst_ip, src_port, exp_port_list))
            if len(exp_port_list) <= 1:
                logging.warning("{} has only {} nexthop".format(dst_ip, exp_port_list))
                assert False

            hit_count_map = {}
            if hash_key == 'ingress-port': # The sample is too little for hash_key ingress-port, check it loose(just verify if the asic actually used the hash field as a load-balancing factor)
                tmp_next_hop = fib[dst_ip]
                tmp_exp_port_list = tmp_next_hop.get_next_hop_list()
                src_ports = list(set(self.setup_info['duts_ptf_ports'][str(dut_index)]) - set(tmp_exp_port_list))
                for src_port in src_ports:
                    logging.info('Checking hash key {}, src_port={}, exp_ports={}, dst_ip={}, dut_index={}'\
                        .format(hash_key, src_port, exp_port_list, dst_ip, dut_index))
                    (matched_index, _) = self.check_ip_route(hash_key, src_port, dst_ip, exp_port_list, dut_index)
                    hit_count_map[matched_index] = hit_count_map.get(matched_index, 0) + 1
                logging.info("hit count map: {}".format(hit_count_map))
                assert True if len(hit_count_map.keys()) == 1 else False
            else:
                for _ in range(0, self.balancing_test_times*len(exp_port_list)):
                    logging.info('Checking hash key {}, src_port={}, exp_ports={}, dst_ip={}, dut_index={}'\
                        .format(hash_key, src_port, exp_port_list, dst_ip, dut_index))
                    (matched_index, _) = self.check_ip_route(hash_key, src_port, dst_ip, exp_port_list, dut_index)
                    hit_count_map[matched_index] = hit_count_map.get(matched_index, 0) + 1
                logging.info("hit count map: {}".format(hit_count_map))

                self.check_balancing(next_hop.get_next_hop(), hit_count_map)

    def check_ip_route(self, hash_key, src_port, dst_ip, dst_port_list, dut_index):
        if ip_network(unicode(dst_ip)).version == 4:
            (matched_index, received) = self.check_ipv4_route(hash_key, src_port, dst_port_list, dut_index)
        else:
            (matched_index, received) = self.check_ipv6_route(hash_key, src_port, dst_port_list, dut_index)

        assert received

        matched_port = dst_port_list[matched_index]
        logging.info("Received packet at " + str(matched_port))
        time.sleep(0.02)

        return (matched_port, received)

    def _get_ip_proto(self, ipv6=False):
        # ip_proto 2 is IGMP, should not be forwarded by router
        # ip_proto 254 is experimental
        # MLNX ASIC can't forward ip_proto 254, BRCM is OK, skip for all for simplicity
        skip_ports = [2, 254]
        if ipv6:
            # Skip ip_proto 0 for IPv6
            skip_ports.append(0)

        while True:
            ip_proto = random.randint(0, 255)
            if ip_proto not in skip_ports:
                return ip_proto

    def check_ipv4_route(self, hash_key, src_port, dst_port_list, dut_index):
        '''
        @summary: Check IPv4 route works.
        @param hash_key: hash key to build packet with.
        @param src_port: index of port to use for sending packet to switch
        @param dst_port_list: list of ports on which to expect packet to come back from the switch
        '''
        base_mac = self.dataplane.get_mac(0, 0)
        ip_src = self.src_ip_interval.get_random_ip() if hash_key == 'src-ip' else self.src_ip_interval.get_first_ip()
        ip_dst = self.dst_ip_interval.get_random_ip() if hash_key == 'dst-ip' else self.dst_ip_interval.get_first_ip()
        sport = random.randint(0, 65535) if hash_key == 'src-port' else 1234
        dport = random.randint(0, 65535) if hash_key == 'dst-port' else 80

        src_mac = (base_mac[:-5] + "%02x" % random.randint(0, 255) + ":" + "%02x" % random.randint(0, 255)) if hash_key == 'src-mac' else base_mac
        router_mac = random.choice(self.dst_macs) if hash_key == 'dst-mac' else self.setup_info['router_mac'][str(dut_index)]
        exp_router_mac = router_mac
        if 'dualtor' in self.setup_info['tbinfo']['topo']['name']:
            if src_port in self.setup_info['vlan_ports'][str(dut_index)]:
                router_mac = self.setup_info['vlan_mac'][str(dut_index)][0]
                active_dut_index = self.ptf_port_dut_map[str(src_port)][0]
                exp_router_mac = self.setup_info['router_mac'][str(active_dut_index)]

        vlan_id = random.choice(self.vlan_ids) if hash_key == 'vlan-id' else 0
        ip_proto = self._get_ip_proto() if hash_key == 'ip-proto' else None



        pkt = simple_tcp_packet(pktlen=100 if vlan_id == 0 else 104,
                            eth_dst=router_mac,
                            eth_src=src_mac,
                            dl_vlan_enable=False if vlan_id == 0 else True,
                            vlan_vid=vlan_id,
                            vlan_pcp=0,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            tcp_sport=sport,
                            tcp_dport=dport,
                            ip_ttl=64)
        exp_pkt = simple_tcp_packet(
                            eth_src=exp_router_mac,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            tcp_sport=sport,
                            tcp_dport=dport,
                            ip_ttl=63)

        if hash_key == 'ip-proto':
            pkt['IP'].proto = ip_proto
            exp_pkt['IP'].proto = ip_proto
        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")

        send_packet(self, src_port, pkt)
        logging.info('Sent Ether(src={}, dst={})/IP(src={}, dst={})/TCP(sport={}, dport={})'\
            .format(pkt.src,
                    pkt.dst,
                    pkt['IP'].src,
                    pkt['IP'].dst,
                    sport,
                    dport))
        logging.info('Expect Ether(src={}, dst={})/IP(src={}, dst={})/TCP(sport={}, dport={})'\
            .format(exp_router_mac,
                    'any',
                    ip_src,
                    ip_dst,
                    sport,
                    dport))

        return verify_packet_any_port(self, masked_exp_pkt, dst_port_list)

    def check_ipv6_route(self, hash_key, src_port, dst_port_list, dut_index):
        '''
        @summary: Check IPv6 route works.
        @param hash_key: hash key to build packet with.
        @param in_port: index of port to use for sending packet to switch
        @param dst_port_list: list of ports on which to expect packet to come back from the switch
        @return Boolean
        '''
        base_mac = self.dataplane.get_mac(0, 0)
        ip_src = self.src_ip_interval.get_random_ip() if hash_key == 'src-ip' else self.src_ip_interval.get_first_ip()
        ip_dst = self.dst_ip_interval.get_random_ip() if hash_key == 'dst-ip' else self.dst_ip_interval.get_first_ip()

        sport = random.randint(0, 65535) if hash_key == 'src-port' else 1234
        dport = random.randint(0, 65535) if hash_key == 'dst-port' else 80

        src_mac = (base_mac[:-5] + "%02x" % random.randint(0, 255) + ":" + "%02x" % random.randint(0, 255)) if hash_key == 'src-mac' else base_mac
        router_mac = self.setup_info['router_mac'][str(dut_index)]
        exp_router_mac = router_mac
        if 'dualtor' in self.setup_info['tbinfo']['topo']['name']:
            if src_port in self.setup_info['vlan_ports'][str(dut_index)]:
                router_mac = self.setup_info['vlan_mac'][str(dut_index)][0]
                active_dut_index = self.ptf_port_dut_map[str(src_port)][0]
                exp_router_mac = self.setup_info['router_mac'][str(active_dut_index)]

        vlan_id = random.choice(self.vlan_ids) if hash_key == 'vlan-id' else 0
        ip_proto = self._get_ip_proto(ipv6=True) if hash_key == "ip-proto" else None

        pkt = simple_tcpv6_packet(pktlen=100 if vlan_id == 0 else 104,
                                eth_dst=router_mac,
                                eth_src=src_mac,
                                dl_vlan_enable=False if vlan_id == 0 else True,
                                vlan_vid=vlan_id,
                                vlan_pcp=0,
                                ipv6_dst=ip_dst,
                                ipv6_src=ip_src,
                                tcp_sport=sport,
                                tcp_dport=dport,
                                ipv6_hlim=64)
        exp_pkt = simple_tcpv6_packet(
                                eth_src=exp_router_mac,
                                ipv6_dst=ip_dst,
                                ipv6_src=ip_src,
                                tcp_sport=sport,
                                tcp_dport=dport,
                                ipv6_hlim=63)

        if hash_key == 'ip-proto':
            pkt['IPv6'].nh = ip_proto
            exp_pkt['IPv6'].nh = ip_proto

        masked_exp_pkt = Mask(exp_pkt)
        masked_exp_pkt.set_do_not_care_scapy(scapy.Ether,"dst")

        send_packet(self, src_port, pkt)
        logging.info('Sent Ether(src={}, dst={})/IPv6(src={}, dst={})/TCP(sport={}, dport={})'\
            .format(pkt.src,
                    pkt.dst,
                    pkt['IPv6'].src,
                    pkt['IPv6'].dst,
                    sport,
                    dport))
        logging.info('Expect Ether(src={}, dst={})/IPv6(src={}, dst={})/TCP(sport={}, dport={})'\
            .format(exp_router_mac,
                    'any',
                    ip_src,
                    ip_dst,
                    sport,
                    dport))

        return verify_packet_any_port(self, masked_exp_pkt, dst_port_list)

    def check_within_expected_range(self, actual, expected):
        '''
        @summary: Check if the actual number is within the accepted range of the expected number
        @param actual : acutal number of recieved packets
        @param expected : expected number of recieved packets
        @return (percentage, bool)
        '''
        percentage = (actual - expected) / float(expected)
        return (percentage, abs(percentage) <= self.balancing_range)

    def check_balancing(self, dest_port_list, port_hit_cnt):
        '''
        @summary: Check if the traffic is balanced across the ECMP groups and the LAG members
        @param dest_port_list : a list of ECMP entries and in each ECMP entry a list of ports
        @param port_hit_cnt : a dict that records the number of packets each port received
        @return bool
        '''

        logging.info("%-10s \t %-10s \t %10s \t %10s \t %10s" % ("type", "port(s)", "exp_cnt", "act_cnt", "diff(%)"))
        result = True

        total_hit_cnt = sum(port_hit_cnt.values())
        for ecmp_entry in dest_port_list:
            total_entry_hit_cnt = 0
            for member in ecmp_entry:
                total_entry_hit_cnt += port_hit_cnt.get(member, 0)
            (p, r) = self.check_within_expected_range(total_entry_hit_cnt, float(total_hit_cnt)/len(dest_port_list))
            logging.info("%-10s \t %-10s \t %10d \t %10d \t %10s"
                        % ("ECMP", str(ecmp_entry), total_hit_cnt/len(dest_port_list), total_entry_hit_cnt, str(round(p, 4)*100) + '%'))
            result &= r
            if len(ecmp_entry) == 1 or total_entry_hit_cnt == 0:
                continue
            for member in ecmp_entry:
                (p, r) = self.check_within_expected_range(port_hit_cnt.get(member, 0), float(total_entry_hit_cnt)/len(ecmp_entry))
                logging.info("%-10s \t %-10s \t %10d \t %10d \t %10s"
                            % ("LAG", str(member), total_entry_hit_cnt/len(ecmp_entry), port_hit_cnt.get(member, 0), str(round(p, 4)*100) + '%'))
                result &= r

        assert result

    def runTest(self):
        """
        @summary: Send packet for each range of both IPv4 and IPv6 spaces and
        expect the packet to be received from one of the expected ports
        """

        for hash_key in self.hash_keys:
            logging.info("hash test hash_key: {}".format(hash_key))
            self.check_hash(hash_key)
