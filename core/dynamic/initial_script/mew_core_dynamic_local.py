from ptf import config
import ptf.testutils as testutils
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as gc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import threading
mac1=0x0800275a18d5
mac2=0xa4fa76061562
mac3=0xa4fa76061563
mac4=0xa4fa76061564
mac5=0x080027557aff
ip1=0xa1a0a0a1
ip2=0xa2a0a0a2
ip3=0xa3a0a0a3
ip4=0xa4a0a0a4
ip5=0xa5a0a0a5
ip6=0xa5a0a0a6
ip7=0xa5a0a0a7
port0=0
port1=1
port2=2
class PortswitchTest(BfRuntimeTest):
    def setUp(self):
        client_id = 0
        self.p4_name='mew_core_dynamic'
        self.table_all_route='SwitchIngress.all_route'
        self.action_route_nat='SwitchIngress.route_nat'
        self.action_remove_vlan='SwitchIngress.remove_vlan'

        self.table_route_mirror='SwitchEgress.route_mirror'
        self.action_mirror_route='SwitchEgress.mirror_route'
        BfRuntimeTest.setUp(self, client_id, self.p4_name)
    def myconnect(self):
        # Get bfrt_info and set it as part of the test
        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)
        self.target = gc.Target(device_id=0, pipe_id=0xffff)
        # get table name
        self.route_mirror_table = self.bfrt_info.table_get(self.table_route_mirror)
        self.all_route_table = self.bfrt_info.table_get(self.table_all_route)
        self.mirror_cfg_table = self.bfrt_info.table_get("$mirror.cfg")
    def my_add_table_entry(self):
        try:
            self.all_route_table.entry_add(
                self.target,
                [self.all_route_table.make_key(
                    [gc.KeyTuple('ig_intr_md.ingress_port', port0)]
                )],
                [self.all_route_table.make_data(
                    [gc.DataTuple('dst_port',port1), gc.DataTuple('dst_addr',mac1)],
                    self.action_route_nat
                )]
            )
            self.all_route_table.entry_add(
                self.target,
                [self.all_route_table.make_key(
                    [gc.KeyTuple('ig_intr_md.ingress_port', port1)]
                )],
                [self.all_route_table.make_data(
                    [gc.DataTuple('dst_port',port0)],
                    self.action_remove_vlan
                )]
            )
            self.mirror_cfg_table.entry_add(self.target, [self.mirror_cfg_table.make_key([gc.KeyTuple('$sid', 11)])], [self.mirror_cfg_table.make_data([
            	gc.DataTuple('$direction', str_val="INGRESS"),
            	gc.DataTuple('$ucast_egress_port', 2),
            	gc.DataTuple('$ucast_egress_port_valid', bool_val=True),
            	gc.DataTuple('$session_enable', bool_val=True),
            ], "$normal")])
            self.mirror_cfg_table.entry_add(self.target, [self.mirror_cfg_table.make_key([gc.KeyTuple('$sid', 12)])], [self.mirror_cfg_table.make_data([
                gc.DataTuple('$direction', str_val="INGRESS"),
                gc.DataTuple('$ucast_egress_port', 10),
                gc.DataTuple('$ucast_egress_port_valid', bool_val=True),
                gc.DataTuple('$session_enable', bool_val=True),
            ], "$normal")])
            self.route_mirror_table.entry_add(
                self.target,
                [self.route_mirror_table.make_key(
                    [gc.KeyTuple('meta.edge_id', 1)]
                )],
                [self.route_mirror_table.make_data(
                    [gc.DataTuple('dst', mac1)],
                    self.action_mirror_route
                )]
            )
            
            
        except Exception as e:
            print(e)
            pass


    def send_entry(self):
        try:
            self.my_add_table_entry()
        except Exception as e:
            print(e)
            
    def runTest(self):
        try:
            self.myconnect()
            self.send_entry()
        except Exception as exc:
            print(exc)

