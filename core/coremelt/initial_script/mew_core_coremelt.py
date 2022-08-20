from ptf import config
import ptf.testutils as testutils
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as gc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import threading

class PortswitchTest(BfRuntimeTest):
    def setUp(self):
        client_id = 0
        self.p4_name='mew_core_coremelt'
        self.table_link_state_update1='SwitchIngress.link_state_update1'
        self.action_lstate1_plus='SwitchIngress.lstate1_plus'
        self.action_lstate1_read='SwitchIngress.lstate1_read'
        self.action_lstate1_update='SwitchIngress.lstate1_update'
        self.table_link_state_update2='SwitchIngress.link_state_update2'
        self.action_lstate2_plus='SwitchIngress.lstate2_plus'
        self.action_lstate2_read='SwitchIngress.lstate2_read'
        self.action_lstate2_update='SwitchIngress.lstate2_update'

        self.table_flow_state_update1='SwitchIngress.flow_state_update1_0'
        self.action_fstate1_plus='SwitchIngress.fstate1_0_plus'
        self.action_fstate1_update='SwitchIngress.fstate1_0_update'
        self.action_fstate1_read='SwitchIngress.fstate1_0_read'
        self.table_flow_state_update2='SwitchIngress.flow_state_update2_0'
        self.action_fstate2_plus='SwitchIngress.fstate2_0_plus'
        self.action_fstate2_update='SwitchIngress.fstate2_0_update'
        self.action_fstate2_read='SwitchIngress.fstate2_0_read'

        self.table_get_defense_info='SwitchIngress.get_defense_info'
        self.action_return_defense_info='SwitchIngress.return_defense_info'
        self.table_get_monitor_type='SwitchIngress.get_monitor_type'
        self.action_return_monitor_type='SwitchIngress.return_monitor_type'
        self.table_blocktable='SwitchIngress.blocktable'
        self.action_return_block_flag='SwitchIngress.return_block_flag'
        self.action_return_stale='SwitchIngress.return_stale'
        self.table_thre_check_coremelt='SwitchIngress.thre_check_coremelt'
        self.action_upload_to_cpu_coremelt='SwitchIngress.upload_to_cpu_coremelt'

        BfRuntimeTest.setUp(self, client_id, self.p4_name)
    def myconnect(self):
        # Get bfrt_info and set it as part of the test
        self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)
        self.target = gc.Target(device_id=0, pipe_id=0xffff)
        # get table name
        self.link_state_update1_table = self.bfrt_info.table_get(self.table_link_state_update1)
        self.link_state_update2_table = self.bfrt_info.table_get(self.table_link_state_update2)
        self.flow_state_update1_table = self.bfrt_info.table_get(self.table_flow_state_update1)
        self.flow_state_update2_table = self.bfrt_info.table_get(self.table_flow_state_update2)
        self.get_defense_info_table = self.bfrt_info.table_get(self.table_get_defense_info)
        self.get_monitor_type_table = self.bfrt_info.table_get(self.table_get_monitor_type)
        self.blocktable_table = self.bfrt_info.table_get(self.table_blocktable)
        self.thre_check_coremelt_table = self.bfrt_info.table_get(self.table_thre_check_coremelt)
    def my_add_table_entry(self):
        try:
            self.link_state_update1_table.entry_add(
                self.target,
                [self.link_state_update1_table.make_key(
                    [gc.KeyTuple('cur_link_time_window', 0), gc.KeyTuple('global_time_window', 0)]
                )],
                [self.link_state_update1_table.make_data(
                    [],
                    self.action_lstate1_plus
                )]
            )
            self.link_state_update1_table.entry_add(
                self.target,
                [self.link_state_update1_table.make_key(
                    [gc.KeyTuple('cur_link_time_window', 0), gc.KeyTuple('global_time_window', 1)]
                )],
                [self.link_state_update1_table.make_data(
                    [],
                    self.action_lstate1_read
                )]
            )
            self.link_state_update1_table.entry_add(
                self.target,
                [self.link_state_update1_table.make_key(
                    [gc.KeyTuple('cur_link_time_window', 1), gc.KeyTuple('global_time_window', 1)]
                )],
                [self.link_state_update1_table.make_data(
                    [],
                    self.action_lstate1_read
                )]
            )
            self.link_state_update1_table.entry_add(
                self.target,
                [self.link_state_update1_table.make_key(
                    [gc.KeyTuple('cur_link_time_window', 1), gc.KeyTuple('global_time_window', 0)]
                )],
                [self.link_state_update1_table.make_data(
                    [],
                    self.action_lstate1_update
                )]
            )
            self.link_state_update2_table.entry_add(
                self.target,
                [self.link_state_update2_table.make_key(
                    [gc.KeyTuple('cur_link_time_window', 0), gc.KeyTuple('global_time_window', 0)]
                )],
                [self.link_state_update2_table.make_data(
                    [],
                    self.action_lstate2_read
                )]
            )
            self.link_state_update2_table.entry_add(
                self.target,
                [self.link_state_update2_table.make_key(
                    [gc.KeyTuple('cur_link_time_window', 0), gc.KeyTuple('global_time_window', 1)]
                )],
                [self.link_state_update2_table.make_data(
                    [],
                    self.action_lstate2_update
                )]
            )
            self.link_state_update2_table.entry_add(
                self.target,
                [self.link_state_update2_table.make_key(
                    [gc.KeyTuple('cur_link_time_window', 1), gc.KeyTuple('global_time_window', 1)]
                )],
                [self.link_state_update2_table.make_data(
                    [],
                    self.action_lstate2_plus
                )]
            )
            self.link_state_update2_table.entry_add(
                self.target,
                [self.link_state_update2_table.make_key(
                    [gc.KeyTuple('cur_link_time_window', 1), gc.KeyTuple('global_time_window', 0)]
                )],
                [self.link_state_update2_table.make_data(
                    [],
                    self.action_lstate2_read
                )]
            )
            
            self.flow_state_update1_table.entry_add(
                self.target,
                [self.flow_state_update1_table.make_key(
                    [ gc.KeyTuple('cur_flow_time_window', 0), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('flow_monitor_flag', 1)]
                )],
                [self.flow_state_update1_table.make_data(
                    [],
                    self.action_fstate1_plus
                )]
            )
            self.flow_state_update1_table.entry_add(
                self.target,
                [self.flow_state_update1_table.make_key(
                    [ gc.KeyTuple('cur_flow_time_window', 0), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('flow_monitor_flag', 1)]
                )],
                [self.flow_state_update1_table.make_data(
                    [],
                    self.action_fstate1_read
                )]
            )
            self.flow_state_update1_table.entry_add(
                self.target,
                [self.flow_state_update1_table.make_key(
                    [ gc.KeyTuple('cur_flow_time_window', 1), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('flow_monitor_flag', 1)]
                )],
                [self.flow_state_update1_table.make_data(
                    [],
                    self.action_fstate1_read
                )]
            )
            self.flow_state_update1_table.entry_add(
                self.target,
                [self.flow_state_update1_table.make_key(
                    [ gc.KeyTuple('cur_flow_time_window', 1), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('flow_monitor_flag', 1)]
                )],
                [self.flow_state_update1_table.make_data(
                    [],
                    self.action_fstate1_update
                )]
            )
            self.flow_state_update2_table.entry_add(
                self.target,
                [self.flow_state_update2_table.make_key(
                    [ gc.KeyTuple('cur_flow_time_window', 1), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('flow_monitor_flag', 1)]
                )],
                [self.flow_state_update2_table.make_data(
                    [],
                    self.action_fstate2_plus
                )]
            )
            self.flow_state_update2_table.entry_add(
                self.target,
                [self.flow_state_update2_table.make_key(
                    [ gc.KeyTuple('cur_flow_time_window', 1), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('flow_monitor_flag', 1)]
                )],
                [self.flow_state_update2_table.make_data(
                    [],
                    self.action_fstate2_read
                )]
            )
            self.flow_state_update2_table.entry_add(
                self.target,
                [self.flow_state_update2_table.make_key(
                    [ gc.KeyTuple('cur_flow_time_window', 0), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('flow_monitor_flag', 1)]
                )],
                [self.flow_state_update2_table.make_data(
                    [],
                    self.action_fstate2_read
                )]
            )
            self.flow_state_update2_table.entry_add(
                self.target,
                [self.flow_state_update2_table.make_key(
                    [ gc.KeyTuple('cur_flow_time_window', 0), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('flow_monitor_flag', 1)]
                )],
                [self.flow_state_update2_table.make_data(
                    [],
                    self.action_fstate2_update
                )]
            )
            self.get_defense_info_table.entry_add(
                self.target,
                [self.get_defense_info_table.make_key(
                    [gc.KeyTuple('ig_intr_md.ingress_port', 1)]
                )],
                [self.get_defense_info_table.make_data(
                    [gc.DataTuple('curv', 1), gc.DataTuple('curt', 2)],
                    self.action_return_defense_info
                )]
            )
            self.get_defense_info_table.entry_add(
                self.target,
                [self.get_defense_info_table.make_key(
                    [gc.KeyTuple('ig_intr_md.ingress_port', 0)]
                )],
                [self.get_defense_info_table.make_data(
                    [gc.DataTuple('curv', 1), gc.DataTuple('curt', 2)],
                    self.action_return_defense_info
                )]
            )
            self.get_monitor_type_table.entry_add(
                self.target,
                [self.get_monitor_type_table.make_key(
                    [gc.KeyTuple('ig_intr_md.ingress_port', 0)]
                )],
                [self.get_monitor_type_table.make_data(
                    [gc.DataTuple('flow_flag', 1)],
                    self.action_return_monitor_type
                )]
            )
            self.get_monitor_type_table.entry_add(
                self.target,
                [self.get_monitor_type_table.make_key(
                    [gc.KeyTuple('ig_intr_md.ingress_port', 1)]
                )],
                [self.get_monitor_type_table.make_data(
                    [gc.DataTuple('flow_flag', 1)],
                    self.action_return_monitor_type
                )]
            )
            self.blocktable_table.entry_add(
                self.target,
                [self.blocktable_table.make_key(
                    [gc.KeyTuple('hdr.ipv4.src_addr', 0xffffffff)]
                )],
                [self.blocktable_table.make_data(
                    [],
                    self.action_return_block_flag
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

