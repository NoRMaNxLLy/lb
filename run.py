from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.app.ofctl.api import get_datapath
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import arp
import ryu.topology.event as topo_event

import networkx as nx
import time
from time import sleep

IDLE_TIMEOUT = 15
HARD_TIMEOUT = 60


class Mapper():
    """ map IPs, macs, port, and datapaths to each other """

    def __init__(self):
        self._ip2mac = {}
        self._ip2dpid = {}  # ip: (dpid, port)

    def ip2mac(self, ip):
        """ return the mac address mapped with the ip """
        if ip not in self._ip2mac:
            return None
        return self._ip2mac[ip]

    def map_ip2mac(self, ip, mac):
        """ map the IP to the Mac """
        self._ip2mac[ip] = mac

    def ip2dpid(self, ip):
        """
        returns the datapath and the port to where ip is connected
        """
        if ip not in self._ip2dpid:
            return None
        return self._ip2dpid[ip]

    def map_ip2dpid(self, ip, dpid, port):
        """ map an IP to a dpid """
        self._ip2dpid[ip] = (dpid, port)


class Pather():
    """ deal with paths. caches paths info """

    def __init__(self):
        self._paths = {}  # (src, dst): { i, paths:[[p1], [p2],...] }

    def add(self, src, dst, path):
        """ add a path from src to dst """

        if not self.exist(src, dst):
            self._paths[src, dst] = {}
            self._paths[src, dst]["i"] = 0
            self._paths[src, dst]["paths"] = []

        self._paths[src, dst]["paths"].append(path)

    def get(self, src, dst):
        """
        return the next available path from src to dst using round
        robin. otherwise return None
        """

        if not self.exist(src, dst):
            return None

        i = self._paths[src, dst]["i"]
        paths = self._paths[src, dst]["paths"]
        path = paths[i % len(paths)]
        self._paths[src, dst]["i"] += 1
        return path

    def getall(self, src, dst):
        """ get all the known paths """
        if not self.exist(src, dst):
            return None

        return self._paths[src, dst]["paths"]

    def exist(self, src, dst):
        """ reports whether a path exists from src to dst """
        if (src, dst) not in self._paths:
            return False
        return True

    def clear(self):
        """ clear all the paths """
        self._paths.clear()


class Balancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Balancer, self).__init__(*args, **kwargs)
        self.G = nx.DiGraph()
        self.M = Mapper()
        self.P = Pather()

    def _arp_handler(self, dp, in_port, pkt):
        """ handle ARP PacketIn's """
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        h = pkt.get_protocol(arp.arp)

        if self.M.ip2dpid(h.dst_ip) is None:
            self.logger.info("dst %s is not known. flooding...", h.dst_ip)
            msg = parser.OFPPacketOut(datapath=dp,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port,
                                      actions=[parser.OFPActionOutput(
                                          ofproto.OFPP_ALL)],
                                      data=pkt.data)
            dp.send_msg(msg)
            self.logger.info("")
            return

        _dpid, _port = self.M.ip2dpid(h.dst_ip)
        _dp = get_datapath(self, _dpid)
        self.logger.info("send ARP message through %s port %s", _dpid,
                         _port)
        msg = parser.OFPPacketOut(datapath=_dp,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=[parser.OFPActionOutput(
                                      _port)],
                                  data=pkt.data)
        _dp.send_msg(msg)
        self.logger.info("")

    def _ip_handler(self, dp, in_port, pkt):
        """ handle IP PacketIn's """
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        h = pkt.get_protocol(ipv4.ipv4)

        if self.M.ip2dpid(h.dst) is None:
            self.logger.info("Mapper does not know where %s connected", h.dst)
            return

        paths = self._lb_findpaths(h.src, h.dst)
        self.logger.info("paths from %s to %s: %s", h.src, h.dst, paths)
        path = self._lb_choose_path(paths)
        self.logger.info("path %s is choosen", path)

        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=h.src,
            ipv4_dst=h.dst)
        self._lb_install_path(path, h.src, h.dst, match)

        # reprocess this packet again
        msg = parser.OFPPacketOut(datapath=dp,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port,
                                  actions=[parser.OFPActionOutput(
                                      ofproto.OFPP_TABLE)],
                                  data=pkt.data)
        dp.send_msg(msg)
        self.logger.info("")

    def _tcp_handler(self, dp, in_port, pkt):
        """ handle TCP PacketIn's """
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        h_ip = pkt.get_protocol(ipv4.ipv4)
        h = pkt.get_protocol(tcp.tcp)

        if self.M.ip2dpid(h_ip.dst) is None:
            self.logger.info("Mapper does not know where %s connected",
                             h_ip.dst)
            return

        path = self._lb_getpath(h_ip.src, h_ip.dst)
        paths = self.P.getall(h_ip.src, h_ip.dst)
        self.logger.info("paths from %s to %s: %s", h_ip.src, h_ip.dst, paths)
        self.logger.info("path %s is choosen", path)

        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=h_ip.src,
            ipv4_dst=h_ip.dst,
            ip_proto=in_proto.IPPROTO_TCP,
            tcp_src=h.src_port,
            tcp_dst=h.dst_port)
        self._lb_install_path(path, h_ip.src, h_ip.dst, match)

        # reverse path
        path = list(reversed(path))
        match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=h_ip.dst,
            ipv4_dst=h_ip.src,
            ip_proto=in_proto.IPPROTO_TCP,
            tcp_src=h.dst_port,
            tcp_dst=h.src_port)
        self._lb_install_path(path, h_ip.dst, h_ip.src, match)

        # reprocess this packet again
        msg = parser.OFPPacketOut(datapath=dp,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port,
                                  actions=[parser.OFPActionOutput(
                                      ofproto.OFPP_TABLE)],
                                  data=pkt.data)
        dp.send_msg(msg)
        self.logger.info("")

    def _lb_getpath(self, src_ip, dst_ip):
        if not self.P.exist(src_ip, dst_ip):
            node1, _ = self.M.ip2dpid(src_ip)
            node2, _ = self.M.ip2dpid(dst_ip)
            paths = list(nx.all_shortest_paths(self.G, node1, node2))
            for p in paths:
                self.P.add(src_ip, dst_ip, p)

        path = self.P.get(src_ip, dst_ip)
        return path

    def _lb_findpaths(self, src_ip, dst_ip):
        node1, _ = self.M.ip2dpid(src_ip)
        node2, _ = self.M.ip2dpid(dst_ip)

        paths = list(nx.all_shortest_paths(self.G, node1, node2))
        return paths

    def _lb_choose_path(self, paths):
        # TODO: do a round robin
        return paths[time.time_ns() % len(paths)]

    # TODO: this mess is not right and needs refactoring....
    def _lb_install_path(self, path, src_ip, dst_ip, match):
        edges = list(zip(path, path[1:]))   # [(s1, s2)...]

        for e in edges:
            dpid = e[0]
            port = self.G.edges[e]["port"]
            dp = get_datapath(self, dpid)
            parser = dp.ofproto_parser
            actions = [parser.OFPActionOutput(port)]

            self.logger.debug("addflow dp %s match %s output port %d",
                              dpid, match, port)
            self.add_flow(dp, prio=10, idle=IDLE_TIMEOUT,
                          hard=HARD_TIMEOUT, match=match, actions=actions)

        # this handles the last datapath, or if the path contains only a
        # single datapath.
        dpid = path[-1]
        port = self.M.ip2dpid(dst_ip)[1]
        self.logger.debug("addflow dp %s match %s output port %d",
                          dpid, match, port)
        dp = get_datapath(self, dpid)
        parser = dp.ofproto_parser
        actions = [parser.OFPActionOutput(port)]
        self.add_flow(dp, prio=10, idle=IDLE_TIMEOUT,
                      hard=HARD_TIMEOUT, match=match, actions=actions)
        # this sleep prevents a problem that i can not explain...
        sleep(0.01)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        """
        """
        dp = ev.msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER,
            ofproto.OFPCML_NO_BUFFER
        )]

        self.add_flow(dp, prio=0, match=match, actions=actions)

    def add_flow(self, dp, tbl=0, prio=0, idle=0, hard=0, match=None,
                 actions=[]):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        if dp is None:
            self.logger.error("add_flow(): no datapath was given")
            return

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=dp, priority=prio,
                                idle_timeout=idle, hard_timeout=hard,
                                match=match, instructions=inst)
        dp.send_msg(mod)

#         if buffer_id:
#             mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
#                                     priority=priority, match=match,
#                                     instructions=inst)
#         else:
#             mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
#                                     match=match, instructions=inst)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)
        in_port = msg.match['in_port']

        # ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            h = pkt.get_protocol(arp.arp)
            self.logger.info(
                "dp %s PacketIn Type ARP opcode %d in_port %s src_ip %s dst_ip %s",
                dp.id, h.opcode, in_port, h.src_ip, h.dst_ip)

            self.M.map_ip2mac(h.src_ip, h.src_mac)
            self.logger.info("Mapped %s to %s", h.src_ip, h.src_mac)
            if self.M.ip2dpid(h.src_ip) is None:
                self.M.map_ip2dpid(h.src_ip, dp.id, in_port)
                self.logger.info("Mapped %s to dp %s port %s",
                                 h.src_ip, dp.id, in_port)

            self._arp_handler(dp, in_port, pkt)
            return

        if ip.proto == in_proto.IPPROTO_TCP:
            h = pkt.get_protocol(tcp.tcp)
            self.logger.info(
                "dp %s PacketIn type TCP in_port %s src %s:%s dst %s:%s",
                dp.id, in_port, ip.src, h.src_port, ip.dst, h.dst_port)
            self._tcp_handler(dp, in_port, pkt)
            return

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            h = pkt.get_protocol(ipv4.ipv4)
            self.logger.info(
                "dp %s PacketIn type IP in_port %s src %s dst %s",
                dp.id, in_port, ip.src, ip.dst)
            self._ip_handler(dp, in_port, pkt)
            return

    @set_ev_cls(topo_event.EventSwitchEnter)
    def _switch_enter_handler(self, ev):
        """
        handle new switches (datapaths)
        """
        dp = ev.switch.dp
        dpid = dp.id

        self.logger.info("new datapath: %s", dpid)
        self.logger.info("adding datapath to Graph: %s", dpid)
        self.G.add_node(dpid)

        self.logger.info("number of nodes: %s\n",
                         self.G.number_of_nodes())

        # Request port/link descriptions, useful for obtaining bandwidth
#         req = ofp_parser.OFPPortDescStatsRequest(switch)
#         switch.send_msg(req)

    @set_ev_cls(topo_event.EventSwitchLeave, MAIN_DISPATCHER)
    def _switch_leave_handler(self, ev):
        """
        handle a datapath leaving the network
        """
        dp = ev.switch.dp
        dpid = dp.id
        self.logger.info("datapath quiting:  %s", dpid)
        self.logger.info("removing datapath from Graph: %s", dpid)
        self.G.remove_node(dpid)

        self.logger.info("number of nodes: %s\n",
                         self.G.number_of_nodes())

    @set_ev_cls(topo_event.EventLinkAdd, MAIN_DISPATCHER)
    def _link_add_handler(self, ev):
        """
        """
        s1 = ev.link.src
        s2 = ev.link.dst

        self.logger.info("adding link: s%s[%s] <--> [%s]s%s",
                         s1.dpid, s1.port_no, s2.port_no, s2.dpid)

        self.G.add_edge(s1.dpid, s2.dpid, port=s1.port_no)

        self.logger.info("number of edges: %s\n",
                         self.G.number_of_edges())

    @set_ev_cls(topo_event.EventLinkDelete, MAIN_DISPATCHER)
    def _link_delete_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst

        self.logger.info("deleting link: s%s[%s] <--> [%s]s%s",
                         s1.dpid, s1.port_no, s2.port_no, s2.dpid)

        self.G.remove_edge(s1.dpid, s2.dpid)
        self.logger.info("number of edges: %s\n",
                         self.G.number_of_edges())


# TODO: the cache of the Mapper should be cleaned periodically
# TODO: document your code...
