from ptf import config
import ptf.testutils as testutils
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as gc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import threading
import os, sys
sys.path.insert(1, os.getcwd()+'/final_code/common')
print(os.getcwd())
import net_config
port0=net_config.sw2_port0
port1=net_config.sw2_port1
port2=net_config.sw2_port2
port_cpu=net_config.sw2_port_cpu
mac1 = net_config.mac1
mac2 = net_config.mac2
mac3 = net_config.mac3
mac4 = net_config.mac4
mac5 = net_config.mac5
ip1 = net_config.ip1
ip2 = net_config.ip2
ip3 = net_config.ip3
ip4 = net_config.ip4
ip5 = net_config.ip5
ip6 = net_config.ip6
ip7 = net_config.ip7
class PortswitchTest(BfRuntimeTest):
    def setUp(self):
        client_id = 0
        self.p4_name='mew_edge_pulsing'
        self.table_all_route='SwitchIngress.all_route'
        self.action_route_nat='SwitchIngress.route_nat'
        self.action_remove_vlan='SwitchIngress.remove_vlan'

        BfRuntimeTest.setUp(self, client_id, self.p4_name)
    def myconnect(self):
        # Get bfrt_info and set it as part of the test
        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)
        self.target = gc.Target(device_id=0, pipe_id=0xffff)
        # get table name
        self.all_route_table = self.bfrt_info.table_get(self.table_all_route)
    def my_add_table_entry(self):
        try:
            self.all_route_table.entry_add(
                self.target,
                [self.all_route_table.make_key(
                    [gc.KeyTuple('ig_intr_md.ingress_port', port0)]
                )],
                [self.all_route_table.make_data(
                    [gc.DataTuple('dst_port',port1), gc.DataTuple('dst_addr',mac5)],
                    self.action_route_nat
                )]
            )
            self.all_route_table.entry_add(
                self.target,
                [self.all_route_table.make_key(
                    [gc.KeyTuple('ig_intr_md.ingress_port', port2)]
                )],
                [self.all_route_table.make_data(
                    [gc.DataTuple('dst_port',port1), gc.DataTuple('dst_addr',mac5)],
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

