from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.app.ofctl.api import get_datapath
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
import ryu.topology.event as topo_event

import networkx as nx
from time import sleep
import sys

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

class Balancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    IDLE_TIMEOUT = 30
    HARD_TIMEOUT = 30

    def __init__(self, *args, **kwargs):
        super(Balancer, self).__init__(*args, **kwargs)
        self.G = nx.DiGraph()
        self.M = Mapper()

    def _lb_choose_path(self, paths):
        # TODO: do a round robin
        return paths[0]

    def _lb_find_paths(self, src_ip, dst_ip):
        node1, _ = self.M.ip2dpid(src_ip)
        node2, _ = self.M.ip2dpid(dst_ip)

        paths = list(nx.all_shortest_paths(self.G, node1, node2))
        return paths

    # TODO: this mess is not right and needs refactoring....
    def _lb_install_path(self, path, src_ip, dst_ip):
        edges = list(zip(path, path[1:]))   # [(s1, s2)...]

        # prepare the packetout message

        for e in edges:
            dpid = e[0]
            port = self.G.edges[e]["port"]
            # send a flow mod to this dp
            dp = get_datapath(self, dpid)
            ofproto = dp.ofproto
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip,
                                    ipv4_dst=dst_ip)
            actions = [parser.OFPActionOutput(port)]

            self.logger.info("addflow dp %s match ipv4_src %s ipv4_dst %s output port %d", dpid, src_ip, dst_ip, port)
            self.add_flow(dp, 10, match, actions)

        # this handles the last datapath, or if the path contains only a
        # single datapath.
        dpid = path[-1]
        port = self.M.ip2dpid(dst_ip)[1]
        self.logger.info("addflow dp %s (last dp) match ipv4_src %s ipv4_dst %s output port %d", dpid, src_ip, dst_ip, port)
        dp = get_datapath(self, dpid)
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip,
                                ipv4_dst=dst_ip)
        actions = [parser.OFPActionOutput(port)]
        self.add_flow(dp, 10, match, actions)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        """
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER,
            ofproto.OFPCML_NO_BUFFER
            )]

        self.add_flow(datapath, 0, match, actions)

        # TODO: make ARP packet OUTPUT NORMAL for now
        match = parser.OFPMatch(
                eth_type=0x0806
                )
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 10, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

#         inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
#                                              actions)]

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_WRITE_ACTIONS,
                                      actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)
        in_port = msg.match['in_port']

        # ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self.logger.info(
                "dp %s PacketIn reason %s in_port %s ipv4_src %s ipv4_dst %s",
                dp.id, msg.reason, in_port, ip.src, ip.dst)

        # learn the addresses in this messages.
        # if ARP Requset:
        # * we map the ip to the mac, ip to datapath and port.
        # * if the request address is in the table,
        #
        # if ARP Reply:
        # * map the ip to the mac, ip to datapath and port
        #
        # if IP packet...
        #

        self.M.map_ip2mac(ip.src, eth.src)
        self.logger.info("Mapped %s to %s", ip.src, eth.src)
        self.M.map_ip2mac(ip.dst, eth.dst)
        self.logger.info("Mapped %s to %s", ip.dst, eth.dst)
        self.M.map_ip2dpid(ip.src, dp.id, in_port)
        self.logger.info("Mapped %s to dp %s port %s", ip.src, dp.id, in_port)

        # find a path through the network for this flow, multiple paths
        # are available, they must be utilized.
        paths = self._lb_find_paths(ip.src, ip.dst)
        self.logger.info("dp %s: paths from %s to %s: %s", dp.id,
                         ip.src, ip.dst, paths)
        path = self._lb_choose_path(paths)
        self.logger.info("path %s is choosen", path)
        self._lb_install_path(path, ip.src, ip.dst)

        msg = parser.OFPPacketOut(datapath=dp,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=[parser.OFPActionOutput(ofproto.OFPP_TABLE)],
                                  data=pkt.data)
        dp.send_msg(msg)

    @set_ev_cls(topo_event.EventSwitchEnter)
    def _switch_enter_handler(self, ev):
        """
        handle new switches (datapaths)
        """
#         self.logger.debug("memebers of %s: ", ev)
#         for a in inspect.getmembers(ev):
#             self.logger.debug("\t %s\n", a)

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
#         self.logger.debug("memebers of %s: ", ev.link.src)
#         for a in inspect.getmembers(ev.link.src):
#             self.logger.debug("\t %s\n", a)

        s1 = ev.link.src
        s2 = ev.link.dst

        self.logger.info("adding link: s%s[%s] <--> [%s]s%s",
                         s1.dpid, s1.port_no, s2.port_no, s2.dpid)

        self.G.add_edge(s1.dpid, s2.dpid, port=s1.port_no)

        self.logger.info("number of edges: %s\n",
                         self.G.number_of_edges())

    @set_ev_cls(topo_event.EventLinkDelete, MAIN_DISPATCHER)
    def _link_delete_handler(self, ev):
        """
        """
        s1 = ev.link.src
        s2 = ev.link.dst

        self.logger.info("deleting link: s%s[%s] <--> [%s]s%s",
                         s1.dpid, s1.port_no, s2.port_no, s2.dpid)

        self.G.remove_edge(s1.dpid, s2.dpid)
        self.logger.info("number of edges: %s\n",
                         self.G.number_of_edges())


# TODO: the cache of the Mapper should be cleaned from time to time....
# TODO: document your code...
# TODO: use idle and hard timeout instead of adding thing permanently
