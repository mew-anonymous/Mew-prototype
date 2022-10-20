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
		self.p4_name='mew_core_crossfire'
		self.table_flow_time_update='SwitchIngress.flow_time_update'
		self.action_flow_time1='SwitchIngress.flow_time1'
		self.action_flow_time0='SwitchIngress.flow_time0'
		self.table_link_state_update1='SwitchIngress.link_state_update1'
		self.action_lstate1_plus='SwitchIngress.lstate1_plus'
		self.action_lstate1_read='SwitchIngress.lstate1_read'
		self.action_lstate1_update='SwitchIngress.lstate1_update'
		self.table_link_state_update2='SwitchIngress.link_state_update2'
		self.action_lstate2_plus='SwitchIngress.lstate2_plus'
		self.action_lstate2_read='SwitchIngress.lstate2_read'
		self.action_lstate2_update='SwitchIngress.lstate2_update'

		self.table_flow_state_update1_0='SwitchIngress.flow_state_update1_0'
		self.action_fstate1_0_plus='SwitchIngress.fstate1_0_plus'
		self.action_fstate1_0_update='SwitchIngress.fstate1_0_update'
		self.action_fstate1_0_read='SwitchIngress.fstate1_0_read'
		self.table_flow_state_update1_1='SwitchIngress.flow_state_update1_1'
		self.action_fstate1_1_plus='SwitchIngress.fstate1_1_plus'
		self.action_fstate1_1_update='SwitchIngress.fstate1_1_update'
		self.action_fstate1_1_read='SwitchIngress.fstate1_1_read'
		self.table_flow_state_update1_2='SwitchIngress.flow_state_update1_2'
		self.action_fstate1_2_plus='SwitchIngress.fstate1_2_plus'
		self.action_fstate1_2_update='SwitchIngress.fstate1_2_update'
		self.action_fstate1_2_read='SwitchIngress.fstate1_2_read'
		self.table_flow_state_update2_0='SwitchIngress.flow_state_update2_0'
		self.action_fstate2_0_plus='SwitchIngress.fstate2_0_plus'
		self.action_fstate2_0_update='SwitchIngress.fstate2_0_update'
		self.action_fstate2_0_read='SwitchIngress.fstate2_0_read'
		self.table_flow_state_update2_1='SwitchIngress.flow_state_update2_1'
		self.action_fstate2_1_plus='SwitchIngress.fstate2_1_plus'
		self.action_fstate2_1_update='SwitchIngress.fstate2_1_update'
		self.action_fstate2_1_read='SwitchIngress.fstate2_1_read'
		self.table_flow_state_update2_2='SwitchIngress.flow_state_update2_2'
		self.action_fstate2_2_plus='SwitchIngress.fstate2_2_plus'
		self.action_fstate2_2_update='SwitchIngress.fstate2_2_update'
		self.action_fstate2_2_read='SwitchIngress.fstate2_2_read'
		
		
		self.table_pattern_state1_update='SwitchIngress.pattern_state1_update'
		self.action_local_hit='SwitchIngress.local_hit'
		self.action_others_hit='SwitchIngress.others_hit'
		self.action_pattern_reset='SwitchIngress.pattern_reset'
		self.action_cur_miss='SwitchIngress.cur_miss'

		self.table_get_defense_info='SwitchIngress.get_defense_info'
		self.action_return_defense_info='SwitchIngress.return_defense_info'
		self.table_blocktable='SwitchIngress.blocktable'
		self.action_return_block_flag='SwitchIngress.return_block_flag'

		BfRuntimeTest.setUp(self, client_id, self.p4_name)
	def myconnect(self):
		# Get bfrt_info and set it as part of the test
		self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)
		self.target = gc.Target(device_id=0, pipe_id=0xffff)
		# get table name
		self.flow_time_update_table = self.bfrt_info.table_get(self.table_flow_time_update)
		self.link_state_update1_table = self.bfrt_info.table_get(self.table_link_state_update1)
		self.link_state_update2_table = self.bfrt_info.table_get(self.table_link_state_update2)
		
		self.flow_state_update1_0_table = self.bfrt_info.table_get(self.table_flow_state_update1_0)
		self.flow_state_update1_1_table = self.bfrt_info.table_get(self.table_flow_state_update1_1)
		self.flow_state_update1_2_table = self.bfrt_info.table_get(self.table_flow_state_update1_2)
		self.flow_state_update2_0_table = self.bfrt_info.table_get(self.table_flow_state_update2_0)
		self.flow_state_update2_1_table = self.bfrt_info.table_get(self.table_flow_state_update2_1)
		self.flow_state_update2_2_table = self.bfrt_info.table_get(self.table_flow_state_update2_2)
		self.pattern_state1_update_table = self.bfrt_info.table_get(self.table_pattern_state1_update)
		self.get_defense_info_table = self.bfrt_info.table_get(self.table_get_defense_info)
		self.blocktable_table = self.bfrt_info.table_get(self.table_blocktable)
	def my_add_table_entry(self):
		try:
			self.flow_time_update_table.entry_add(
				self.target,
				[self.flow_time_update_table.make_key(
					[gc.KeyTuple('global_time_window', 1)]
				)],
				[self.flow_time_update_table.make_data(
					[],
					self.action_flow_time1
				)]
			)
			self.flow_time_update_table.entry_add(
				self.target,
				[self.flow_time_update_table.make_key(
					[gc.KeyTuple('global_time_window', 0)]
				)],
				[self.flow_time_update_table.make_data(
					[],
					self.action_flow_time0
				)]
			)
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
			
			
			self.flow_state_update1_0_table.entry_add(
				self.target,
				[self.flow_state_update1_0_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window', 0), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('flow_level', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update1_0_table.make_data(
					[],
					self.action_fstate1_0_plus
				)]
			)
			self.flow_state_update1_0_table.entry_add(
				self.target,
				[self.flow_state_update1_0_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window', 0), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('flow_level', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update1_0_table.make_data(
					[],
					self.action_fstate1_0_read
				)]
			)
			self.flow_state_update1_0_table.entry_add(
				self.target,
				[self.flow_state_update1_0_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  1), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('flow_level', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update1_0_table.make_data(
					[],
					self.action_fstate1_0_read
				)]
			)
			self.flow_state_update1_0_table.entry_add(
				self.target,
				[self.flow_state_update1_0_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  1), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('flow_level', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update1_0_table.make_data(
					[],
					self.action_fstate1_0_update
				)]
			)
			self.flow_state_update1_1_table.entry_add(
				self.target,
				[self.flow_state_update1_1_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  0), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('flow_level', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update1_1_table.make_data(
					[],
					self.action_fstate1_1_plus
				)]
			)
			self.flow_state_update1_1_table.entry_add(
				self.target,
				[self.flow_state_update1_1_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  0), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('flow_level', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update1_1_table.make_data(
					[],
					self.action_fstate1_1_read
				)]
			)
			self.flow_state_update1_1_table.entry_add(
				self.target,
				[self.flow_state_update1_1_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  1), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('flow_level', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update1_1_table.make_data(
					[],
					self.action_fstate1_1_read
				)]
			)
			self.flow_state_update1_1_table.entry_add(
				self.target,
				[self.flow_state_update1_1_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  1), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('flow_level', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update1_1_table.make_data(
					[],
					self.action_fstate1_1_update
				)]
			)
			self.flow_state_update1_2_table.entry_add(
				self.target,
				[self.flow_state_update1_2_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  0), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('flow_level', 2), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update1_2_table.make_data(
					[],
					self.action_fstate1_2_plus
				)]
			)
			self.flow_state_update1_2_table.entry_add(
				self.target,
				[self.flow_state_update1_2_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  0), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('flow_level', 2), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update1_2_table.make_data(
					[],
					self.action_fstate1_2_read
				)]
			)
			self.flow_state_update1_2_table.entry_add(
				self.target,
				[self.flow_state_update1_2_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  1), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('flow_level', 2), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update1_2_table.make_data(
					[],
					self.action_fstate1_2_read
				)]
			)
			self.flow_state_update1_2_table.entry_add(
				self.target,
				[self.flow_state_update1_2_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  1), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('flow_level', 2), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update1_2_table.make_data(
					[],
					self.action_fstate1_2_update
				)]
			)
			self.flow_state_update1_2_table.entry_add(
				self.target,
				[self.flow_state_update1_2_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  0), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('flow_level', 3), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update1_2_table.make_data(
					[],
					self.action_fstate1_2_plus
				)]
			)
			self.flow_state_update1_2_table.entry_add(
				self.target,
				[self.flow_state_update1_2_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  0), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('flow_level', 3), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update1_2_table.make_data(
					[],
					self.action_fstate1_2_read
				)]
			)
			self.flow_state_update1_2_table.entry_add(
				self.target,
				[self.flow_state_update1_2_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  1), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('flow_level', 3), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update1_2_table.make_data(
					[],
					self.action_fstate1_2_read
				)]
			)
			self.flow_state_update1_2_table.entry_add(
				self.target,
				[self.flow_state_update1_2_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  1), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('flow_level', 3), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update1_2_table.make_data(
					[],
					self.action_fstate1_2_update
				)]
			)
			self.flow_state_update2_0_table.entry_add(
				self.target,
				[self.flow_state_update2_0_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  1), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('flow_level', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update2_0_table.make_data(
					[],
					self.action_fstate2_0_plus
				)]
			)
			self.flow_state_update2_0_table.entry_add(
				self.target,
				[self.flow_state_update2_0_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  1), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('flow_level', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update2_0_table.make_data(
					[],
					self.action_fstate2_0_read
				)]
			)
			self.flow_state_update2_0_table.entry_add(
				self.target,
				[self.flow_state_update2_0_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  0), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('flow_level', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update2_0_table.make_data(
					[],
					self.action_fstate2_0_read
				)]
			)
			self.flow_state_update2_0_table.entry_add(
				self.target,
				[self.flow_state_update2_0_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  0), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('flow_level', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update2_0_table.make_data(
					[],
					self.action_fstate2_0_update
				)]
			)
			self.flow_state_update2_1_table.entry_add(
				self.target,
				[self.flow_state_update2_1_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  1), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('flow_level', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update2_1_table.make_data(
					[],
					self.action_fstate2_1_plus
				)]
			)
			self.flow_state_update2_1_table.entry_add(
				self.target,
				[self.flow_state_update2_1_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  1), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('flow_level', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update2_1_table.make_data(
					[],
					self.action_fstate2_1_read
				)]
			)
			self.flow_state_update2_1_table.entry_add(
				self.target,
				[self.flow_state_update2_1_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  0), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('flow_level', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update2_1_table.make_data(
					[],
					self.action_fstate2_1_read
				)]
			)
			self.flow_state_update2_1_table.entry_add(
				self.target,
				[self.flow_state_update2_1_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  0), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('flow_level', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update2_1_table.make_data(
					[],
					self.action_fstate2_1_update
				)]
			)
			self.flow_state_update2_2_table.entry_add(
				self.target,
				[self.flow_state_update2_2_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  1), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('flow_level', 2), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update2_2_table.make_data(
					[],
					self.action_fstate2_2_plus
				)]
			)
			self.flow_state_update2_2_table.entry_add(
				self.target,
				[self.flow_state_update2_2_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  1), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('flow_level', 2), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update2_2_table.make_data(
					[],
					self.action_fstate2_2_read
				)]
			)
			self.flow_state_update2_2_table.entry_add(
				self.target,
				[self.flow_state_update2_2_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  0), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('flow_level', 2), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update2_2_table.make_data(
					[],
					self.action_fstate2_2_read
				)]
			)
			self.flow_state_update2_2_table.entry_add(
				self.target,
				[self.flow_state_update2_2_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  0), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('flow_level', 2), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update2_2_table.make_data(
					[],
					self.action_fstate2_2_update
				)]
			)
			self.flow_state_update2_2_table.entry_add(
				self.target,
				[self.flow_state_update2_2_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  1), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('flow_level', 3), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update2_2_table.make_data(
					[],
					self.action_fstate2_2_plus
				)]
			)
			self.flow_state_update2_2_table.entry_add(
				self.target,
				[self.flow_state_update2_2_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  1), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('flow_level', 3), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update2_2_table.make_data(
					[],
					self.action_fstate2_2_read
				)]
			)
			self.flow_state_update2_2_table.entry_add(
				self.target,
				[self.flow_state_update2_2_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  0), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('flow_level', 3), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update2_2_table.make_data(
					[],
					self.action_fstate2_2_read
				)]
			)
			self.flow_state_update2_2_table.entry_add(
				self.target,
				[self.flow_state_update2_2_table.make_key(
					[ gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('cur_flow_time_window',  0), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('flow_level', 3), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE)]
				)],
				[self.flow_state_update2_2_table.make_data(
					[],
					self.action_fstate2_2_update
				)]
			)
			for key_1 in [0,1]:
				for key_2 in [0,1]:
					for key_3 in [0,net_config.DEFENSETYPE_CROSSFIRE]:
						for key_4 in [0]:
							self.flow_state_update1_0_table.entry_add(
								self.target,
								[self.flow_state_update1_0_table.make_key(
									[  gc.KeyTuple('cur_flow_time_window', key_1), gc.KeyTuple('global_time_window', key_2), gc.KeyTuple('cur_defense_type', key_3+128), gc.KeyTuple('flow_level', key_4), gc.KeyTuple('flow_monitor_flag', 1)]
								)],
								[self.flow_state_update1_0_table.make_data(
									[],
									self.action_fstate1_0_update
								)]
							)
			for key_1 in [0,1]:
				for key_2 in [0,1]:
					for key_3 in [0,net_config.DEFENSETYPE_CROSSFIRE]:
						for key_4 in [1]:
							self.flow_state_update1_1_table.entry_add(
								self.target,
								[self.flow_state_update1_1_table.make_key(
									[  gc.KeyTuple('cur_flow_time_window', key_1), gc.KeyTuple('global_time_window', key_2), gc.KeyTuple('cur_defense_type', key_3+128), gc.KeyTuple('flow_level', key_4), gc.KeyTuple('flow_monitor_flag', 1)]
								)],
								[self.flow_state_update1_1_table.make_data(
									[],
									self.action_fstate1_1_update
								)]
							)
			for key_1 in [0,1]:
				for key_2 in [0,1]:
					for key_3 in [0,net_config.DEFENSETYPE_CROSSFIRE]:
						for key_4 in [2,3]:
							self.flow_state_update1_2_table.entry_add(
								self.target,
								[self.flow_state_update1_2_table.make_key(
									[  gc.KeyTuple('cur_flow_time_window', key_1), gc.KeyTuple('global_time_window', key_2), gc.KeyTuple('cur_defense_type', key_3+128), gc.KeyTuple('flow_level', key_4), gc.KeyTuple('flow_monitor_flag', 1)]
								)],
								[self.flow_state_update1_2_table.make_data(
									[],
									self.action_fstate1_2_update
								)]
							)
			for key_1 in [0,1]:
				for key_2 in [0,1]:
					for key_3 in [0,net_config.DEFENSETYPE_CROSSFIRE]:
						for key_4 in [0]:
							self.flow_state_update2_0_table.entry_add(
								self.target,
								[self.flow_state_update2_0_table.make_key(
									[  gc.KeyTuple('cur_flow_time_window', key_1), gc.KeyTuple('global_time_window', key_2), gc.KeyTuple('cur_defense_type', key_3+128), gc.KeyTuple('flow_level', key_4), gc.KeyTuple('flow_monitor_flag', 1)]
								)],
								[self.flow_state_update2_0_table.make_data(
									[],
									self.action_fstate2_0_update
								)]
							)
			for key_1 in [0,1]:
				for key_2 in [0,1]:
					for key_3 in [0,net_config.DEFENSETYPE_CROSSFIRE]:
						for key_4 in [1]:
							self.flow_state_update2_1_table.entry_add(
								self.target,
								[self.flow_state_update2_1_table.make_key(
									[  gc.KeyTuple('cur_flow_time_window', key_1), gc.KeyTuple('global_time_window', key_2), gc.KeyTuple('cur_defense_type', key_3+128), gc.KeyTuple('flow_level', key_4), gc.KeyTuple('flow_monitor_flag', 1)]
								)],
								[self.flow_state_update2_1_table.make_data(
									[],
									self.action_fstate2_1_update
								)]
							)
			for key_1 in [0,1]:
				for key_2 in [0,1]:
					for key_3 in [0,net_config.DEFENSETYPE_CROSSFIRE]:
						for key_4 in [2,3]:
							self.flow_state_update2_2_table.entry_add(
								self.target,
								[self.flow_state_update2_2_table.make_key(
									[  gc.KeyTuple('cur_flow_time_window', key_1), gc.KeyTuple('global_time_window', key_2), gc.KeyTuple('cur_defense_type', key_3+128), gc.KeyTuple('flow_level', key_4), gc.KeyTuple('flow_monitor_flag', 1)]
								)],
								[self.flow_state_update2_2_table.make_data(
									[],
									self.action_fstate2_2_update
								)]
							)
			for key_1 in [0,1]:
				for key_2 in [0,1]:
						self.pattern_state1_update_table.entry_add(
							self.target,
							[self.pattern_state1_update_table.make_key(
								[gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('flow_state_0', 0),gc.KeyTuple('cur_flow_time_window', 1),gc.KeyTuple('hdr.cd.hit', key_1),gc.KeyTuple('hdr.cd.state1[0:0]', 0),gc.KeyTuple('global_pattern_time_window', key_2),gc.KeyTuple('cur_pattern_time_window', key_2)]
							)],
							[self.pattern_state1_update_table.make_data(
								[],
								self.action_local_hit
							)]
						)
			for key_1 in [0,1]:
				for key_2 in [0,1]:
						self.pattern_state1_update_table.entry_add(
							self.target,
							[self.pattern_state1_update_table.make_key(
								[gc.KeyTuple('flow_monitor_flag', 0), gc.KeyTuple('flow_state_0', 0),gc.KeyTuple('cur_flow_time_window', key_1),gc.KeyTuple('hdr.cd.hit', 1),gc.KeyTuple('hdr.cd.state1[0:0]', 1),gc.KeyTuple('global_pattern_time_window', key_2),gc.KeyTuple('cur_pattern_time_window', key_2)]
							)],
							[self.pattern_state1_update_table.make_data(
								[],
								self.action_others_hit
							)]
						)
			for key_1 in [0,1]:
				for key_2 in [0,1]:
						self.pattern_state1_update_table.entry_add(
							self.target,
							[self.pattern_state1_update_table.make_key(
								[gc.KeyTuple('flow_monitor_flag', 1), gc.KeyTuple('flow_state_0', 0),gc.KeyTuple('cur_flow_time_window', 1),gc.KeyTuple('hdr.cd.hit', key_1),gc.KeyTuple('hdr.cd.state1[0:0]', 0),gc.KeyTuple('global_pattern_time_window', key_2),gc.KeyTuple('cur_pattern_time_window', key_2^1)]
							)],
							[self.pattern_state1_update_table.make_data(
								[],
								self.action_pattern_reset
							)]
						)
			for key_1 in [0,1]:
				for key_2 in [0,1]:
						self.pattern_state1_update_table.entry_add(
							self.target,
							[self.pattern_state1_update_table.make_key(
								[gc.KeyTuple('flow_monitor_flag', 0), gc.KeyTuple('flow_state_0', 0),gc.KeyTuple('cur_flow_time_window', key_1),gc.KeyTuple('hdr.cd.hit', 1),gc.KeyTuple('hdr.cd.state1[0:0]', 1),gc.KeyTuple('global_pattern_time_window', key_2),gc.KeyTuple('cur_pattern_time_window', key_2^1)]
							)],
							[self.pattern_state1_update_table.make_data(
								[],
								self.action_pattern_reset
							)]
						)
			self.get_defense_info_table.entry_add(
				self.target,
				[self.get_defense_info_table.make_key(
					[gc.KeyTuple('ig_intr_md.ingress_port', port1)]
				)],
				[self.get_defense_info_table.make_data(
					[gc.DataTuple('curv', 1), gc.DataTuple('curt', net_config.DEFENSETYPE_CROSSFIRE), gc.DataTuple('curid', net_config.sw2_id)],
					self.action_return_defense_info
				)]
			)
			self.get_defense_info_table.entry_add(
				self.target,
				[self.get_defense_info_table.make_key(
					[gc.KeyTuple('ig_intr_md.ingress_port', port0)]
				)],
				[self.get_defense_info_table.make_data(
					[gc.DataTuple('curv', 1), gc.DataTuple('curt', net_config.DEFENSETYPE_CROSSFIRE), gc.DataTuple('curid', net_config.sw2_id)],
					self.action_return_defense_info
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

