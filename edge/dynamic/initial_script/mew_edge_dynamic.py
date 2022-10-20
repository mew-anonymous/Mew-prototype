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
		self.p4_name='mew_edge_dynamic'
		self.table_flow_time_update='SwitchIngress.flow_time_update'
		self.table_congestion_flow_time_update='SwitchIngress.congestion_flow_time_update'
		self.action_flow_time1='SwitchIngress.flow_time1'
		self.action_flow_time0='SwitchIngress.flow_time0'
		self.action_congestion_flow_time1='SwitchIngress.congestion_flow_time1'
		self.action_congestion_flow_time0='SwitchIngress.congestion_flow_time0'
		self.table_link_state_update1='SwitchIngress.link_state_update1'
		self.action_lstate1_plus='SwitchIngress.lstate1_plus'
		self.action_lstate1_read='SwitchIngress.lstate1_read'
		self.action_lstate1_update='SwitchIngress.lstate1_update'
		self.table_link_state_update2='SwitchIngress.link_state_update2'
		self.action_lstate2_plus='SwitchIngress.lstate2_plus'
		self.action_lstate2_read='SwitchIngress.lstate2_read'
		self.action_lstate2_update='SwitchIngress.lstate2_update'

		self.table_flow_state_update1='SwitchIngress.flow_state_update1'
		self.action_fstate1_plus='SwitchIngress.fstate1_plus'
		self.action_fstate1_update='SwitchIngress.fstate1_update'
		self.action_fstate1_read='SwitchIngress.fstate1_read'
		self.action_fstate1_clear='SwitchIngress.fstate1_clear'
		self.table_flow_state_update2='SwitchIngress.flow_state_update2'
		self.action_fstate2_plus='SwitchIngress.fstate2_plus'
		self.action_fstate2_update='SwitchIngress.fstate2_update'
		self.action_fstate2_read='SwitchIngress.fstate2_read'
		self.action_fstate2_clear='SwitchIngress.fstate2_clear'

		self.table_flow_state_congestion_update1='SwitchIngress.flow_state_congestion_update1'
		self.action_fstate1_congestion_plus='SwitchIngress.fstate1_congestion_plus'
		self.action_fstate1_congestion_update='SwitchIngress.fstate1_congestion_update'
		self.action_fstate1_congestion_read='SwitchIngress.fstate1_congestion_read'
		self.action_fstate1_congestion_clear='SwitchIngress.fstate1_congestion_clear'
		self.table_flow_state_congestion_update2='SwitchIngress.flow_state_congestion_update2'
		self.action_fstate2_congestion_plus='SwitchIngress.fstate2_congestion_plus'
		self.action_fstate2_congestion_update='SwitchIngress.fstate2_congestion_update'
		self.action_fstate2_congestion_read='SwitchIngress.fstate2_congestion_read'
		self.action_fstate2_congestion_clear='SwitchIngress.fstate2_congestion_clear'
		self.table_get_defense_info='SwitchIngress.get_defense_info'
		self.action_return_defense_info='SwitchIngress.return_defense_info'
		self.table_blocktable='SwitchIngress.blocktable'
		self.action_return_block_flag='SwitchIngress.return_block_flag'
		
		self.table_dup_filter='SwitchIngress.dup_filter'
		self.action_check_return0='SwitchIngress.check_return0'
		self.action_check_return1='SwitchIngress.check_return1'
		BfRuntimeTest.setUp(self, client_id, self.p4_name)
	def myconnect(self):
		# Get bfrt_info and set it as part of the test
		self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)
		self.target = gc.Target(device_id=0, pipe_id=0xffff)
		# get table name
		self.flow_time_update_table = self.bfrt_info.table_get(self.table_flow_time_update)
		self.congestion_flow_time_update_table = self.bfrt_info.table_get(self.table_congestion_flow_time_update)
		self.link_state_update1_table = self.bfrt_info.table_get(self.table_link_state_update1)
		self.link_state_update2_table = self.bfrt_info.table_get(self.table_link_state_update2)
		self.flow_state_update1_table = self.bfrt_info.table_get(self.table_flow_state_update1)
		self.flow_state_update2_table = self.bfrt_info.table_get(self.table_flow_state_update2)
		self.flow_state_congestion_update1_table = self.bfrt_info.table_get(self.table_flow_state_congestion_update1)
		self.flow_state_congestion_update2_table = self.bfrt_info.table_get(self.table_flow_state_congestion_update2)
		self.get_defense_info_table = self.bfrt_info.table_get(self.table_get_defense_info)
		self.blocktable_table = self.bfrt_info.table_get(self.table_blocktable)
		self.dup_filter_table = self.bfrt_info.table_get(self.table_dup_filter)
	def my_add_table_entry(self):
		try:
			self.flow_time_update_table.entry_add(
				self.target,
				[self.flow_time_update_table.make_key(
					[gc.KeyTuple('global_flow_time_window', 1)]
				)],
				[self.flow_time_update_table.make_data(
					[],
					self.action_flow_time1
				)]
			)
			self.flow_time_update_table.entry_add(
				self.target,
				[self.flow_time_update_table.make_key(
					[gc.KeyTuple('global_flow_time_window', 0)]
				)],
				[self.flow_time_update_table.make_data(
					[],
					self.action_flow_time0
				)]
			)
			self.congestion_flow_time_update_table.entry_add(
				self.target,
				[self.congestion_flow_time_update_table.make_key(
					[gc.KeyTuple('global_congestion_time_window', 1)]
				)],
				[self.congestion_flow_time_update_table.make_data(
					[],
					self.action_congestion_flow_time1
				)]
			)
			self.congestion_flow_time_update_table.entry_add(
				self.target,
				[self.congestion_flow_time_update_table.make_key(
					[gc.KeyTuple('global_congestion_time_window', 0)]
				)],
				[self.congestion_flow_time_update_table.make_data(
					[],
					self.action_congestion_flow_time0
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
			
			
			self.flow_state_congestion_update1_table.entry_add(
				self.target,
				[self.flow_state_congestion_update1_table.make_key(
					[  gc.KeyTuple('cur_congestion_flow_time', 0), gc.KeyTuple('global_congestion_time_window', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 0)]
				)],
				[self.flow_state_congestion_update1_table.make_data(
					[],
					self.action_fstate1_congestion_plus
				)]
			)
			self.flow_state_congestion_update1_table.entry_add(
				self.target,
				[self.flow_state_congestion_update1_table.make_key(
					[  gc.KeyTuple('cur_congestion_flow_time', 0), gc.KeyTuple('global_congestion_time_window', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 0)]
				)],
				[self.flow_state_congestion_update1_table.make_data(
					[],
					self.action_fstate1_congestion_read
				)]
			)
			self.flow_state_congestion_update1_table.entry_add(
				self.target,
				[self.flow_state_congestion_update1_table.make_key(
					[  gc.KeyTuple('cur_congestion_flow_time', 1), gc.KeyTuple('global_congestion_time_window', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 0)]
				)],
				[self.flow_state_congestion_update1_table.make_data(
					[],
					self.action_fstate1_congestion_read
				)]
			)
			self.flow_state_congestion_update1_table.entry_add(
				self.target,
				[self.flow_state_congestion_update1_table.make_key(
					[  gc.KeyTuple('cur_congestion_flow_time', 1), gc.KeyTuple('global_congestion_time_window', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 0)]
				)],
				[self.flow_state_congestion_update1_table.make_data(
					[],
					self.action_fstate1_congestion_update
				)]
			)
			self.flow_state_congestion_update2_table.entry_add(
				self.target,
				[self.flow_state_congestion_update2_table.make_key(
					[  gc.KeyTuple('cur_congestion_flow_time', 1), gc.KeyTuple('global_congestion_time_window', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 0)]
				)],
				[self.flow_state_congestion_update2_table.make_data(
					[],
					self.action_fstate2_congestion_plus
				)]
			)
			self.flow_state_congestion_update2_table.entry_add(
				self.target,
				[self.flow_state_congestion_update2_table.make_key(
					[  gc.KeyTuple('cur_congestion_flow_time', 1), gc.KeyTuple('global_congestion_time_window', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 0)]
				)],
				[self.flow_state_congestion_update2_table.make_data(
					[],
					self.action_fstate2_congestion_read
				)]
			)
			self.flow_state_congestion_update2_table.entry_add(
				self.target,
				[self.flow_state_congestion_update2_table.make_key(
					[  gc.KeyTuple('cur_congestion_flow_time', 0), gc.KeyTuple('global_congestion_time_window', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 0)]
				)],
				[self.flow_state_congestion_update2_table.make_data(
					[],
					self.action_fstate2_congestion_read
				)]
			)
			self.flow_state_congestion_update2_table.entry_add(
				self.target,
				[self.flow_state_congestion_update2_table.make_key(
					[  gc.KeyTuple('cur_congestion_flow_time', 0), gc.KeyTuple('global_congestion_time_window', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 0)]
				)],
				[self.flow_state_congestion_update2_table.make_data(
					[],
					self.action_fstate2_congestion_update
				)]
			)
			self.flow_state_congestion_update1_table.entry_add(
				self.target,
				[self.flow_state_congestion_update1_table.make_key(
					[  gc.KeyTuple('cur_congestion_flow_time', 0), gc.KeyTuple('global_congestion_time_window', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 1)]
				)],
				[self.flow_state_congestion_update1_table.make_data(
					[],
					self.action_fstate1_congestion_plus
				)]
			)
			self.flow_state_congestion_update1_table.entry_add(
				self.target,
				[self.flow_state_congestion_update1_table.make_key(
					[  gc.KeyTuple('cur_congestion_flow_time', 0), gc.KeyTuple('global_congestion_time_window', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 1)]
				)],
				[self.flow_state_congestion_update1_table.make_data(
					[],
					self.action_fstate1_congestion_read
				)]
			)
			self.flow_state_congestion_update1_table.entry_add(
				self.target,
				[self.flow_state_congestion_update1_table.make_key(
					[  gc.KeyTuple('cur_congestion_flow_time', 1), gc.KeyTuple('global_congestion_time_window', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 1)]
				)],
				[self.flow_state_congestion_update1_table.make_data(
					[],
					self.action_fstate1_congestion_read
				)]
			)
			self.flow_state_congestion_update1_table.entry_add(
				self.target,
				[self.flow_state_congestion_update1_table.make_key(
					[  gc.KeyTuple('cur_congestion_flow_time', 1), gc.KeyTuple('global_congestion_time_window', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 1)]
				)],
				[self.flow_state_congestion_update1_table.make_data(
					[],
					self.action_fstate1_congestion_update
				)]
			)
			self.flow_state_congestion_update2_table.entry_add(
				self.target,
				[self.flow_state_congestion_update2_table.make_key(
					[  gc.KeyTuple('cur_congestion_flow_time', 1), gc.KeyTuple('global_congestion_time_window', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 1)]
				)],
				[self.flow_state_congestion_update2_table.make_data(
					[],
					self.action_fstate2_congestion_plus
				)]
			)
			self.flow_state_congestion_update2_table.entry_add(
				self.target,
				[self.flow_state_congestion_update2_table.make_key(
					[  gc.KeyTuple('cur_congestion_flow_time', 1), gc.KeyTuple('global_congestion_time_window', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 1)]
				)],
				[self.flow_state_congestion_update2_table.make_data(
					[],
					self.action_fstate2_congestion_read
				)]
			)
			self.flow_state_congestion_update2_table.entry_add(
				self.target,
				[self.flow_state_congestion_update2_table.make_key(
					[  gc.KeyTuple('cur_congestion_flow_time', 0), gc.KeyTuple('global_congestion_time_window', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 1)]
				)],
				[self.flow_state_congestion_update2_table.make_data(
					[],
					self.action_fstate2_congestion_read
				)]
			)
			self.flow_state_congestion_update2_table.entry_add(
				self.target,
				[self.flow_state_congestion_update2_table.make_key(
					[  gc.KeyTuple('cur_congestion_flow_time', 0), gc.KeyTuple('global_congestion_time_window', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 1)]
				)],
				[self.flow_state_congestion_update2_table.make_data(
					[],
					self.action_fstate2_congestion_update
				)]
			)
			self.flow_state_congestion_update1_table.entry_add(
				self.target,
				[self.flow_state_congestion_update1_table.make_key(
					[  gc.KeyTuple('cur_congestion_flow_time', 0), gc.KeyTuple('global_congestion_time_window', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE), gc.KeyTuple('flow_level', 1)]
				)],
				[self.flow_state_congestion_update1_table.make_data(
					[],
					self.action_fstate1_congestion_plus
				)]
			)
			self.flow_state_congestion_update1_table.entry_add(
				self.target,
				[self.flow_state_congestion_update1_table.make_key(
					[  gc.KeyTuple('cur_congestion_flow_time', 0), gc.KeyTuple('global_congestion_time_window', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE), gc.KeyTuple('flow_level', 1)]
				)],
				[self.flow_state_congestion_update1_table.make_data(
					[],
					self.action_fstate1_congestion_read
				)]
			)
			self.flow_state_congestion_update1_table.entry_add(
				self.target,
				[self.flow_state_congestion_update1_table.make_key(
					[  gc.KeyTuple('cur_congestion_flow_time', 1), gc.KeyTuple('global_congestion_time_window', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE), gc.KeyTuple('flow_level', 1)]
				)],
				[self.flow_state_congestion_update1_table.make_data(
					[],
					self.action_fstate1_congestion_read
				)]
			)
			self.flow_state_congestion_update1_table.entry_add(
				self.target,
				[self.flow_state_congestion_update1_table.make_key(
					[  gc.KeyTuple('cur_congestion_flow_time', 1), gc.KeyTuple('global_congestion_time_window', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE), gc.KeyTuple('flow_level', 1)]
				)],
				[self.flow_state_congestion_update1_table.make_data(
					[],
					self.action_fstate1_congestion_update
				)]
			)
			self.flow_state_congestion_update2_table.entry_add(
				self.target,
				[self.flow_state_congestion_update2_table.make_key(
					[  gc.KeyTuple('cur_congestion_flow_time', 1), gc.KeyTuple('global_congestion_time_window', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE), gc.KeyTuple('flow_level', 1)]
				)],
				[self.flow_state_congestion_update2_table.make_data(
					[],
					self.action_fstate2_congestion_plus
				)]
			)
			self.flow_state_congestion_update2_table.entry_add(
				self.target,
				[self.flow_state_congestion_update2_table.make_key(
					[  gc.KeyTuple('cur_congestion_flow_time', 1), gc.KeyTuple('global_congestion_time_window', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE), gc.KeyTuple('flow_level', 1)]
				)],
				[self.flow_state_congestion_update2_table.make_data(
					[],
					self.action_fstate2_congestion_read
				)]
			)
			self.flow_state_congestion_update2_table.entry_add(
				self.target,
				[self.flow_state_congestion_update2_table.make_key(
					[  gc.KeyTuple('cur_congestion_flow_time', 0), gc.KeyTuple('global_congestion_time_window', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE), gc.KeyTuple('flow_level', 1)]
				)],
				[self.flow_state_congestion_update2_table.make_data(
					[],
					self.action_fstate2_congestion_read
				)]
			)
			self.flow_state_congestion_update2_table.entry_add(
				self.target,
				[self.flow_state_congestion_update2_table.make_key(
					[  gc.KeyTuple('cur_congestion_flow_time', 0), gc.KeyTuple('global_congestion_time_window', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE), gc.KeyTuple('flow_level', 1)]
				)],
				[self.flow_state_congestion_update2_table.make_data(
					[],
					self.action_fstate2_congestion_update
				)]
			)
			self.flow_state_update1_table.entry_add(
				self.target,
				[self.flow_state_update1_table.make_key(
					[  gc.KeyTuple('cur_flow_time_window', 0), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE), gc.KeyTuple('flow_level', 0)]
				)],
				[self.flow_state_update1_table.make_data(
					[],
					self.action_fstate1_plus
				)]
			)
			self.flow_state_update1_table.entry_add(
				self.target,
				[self.flow_state_update1_table.make_key(
					[  gc.KeyTuple('cur_flow_time_window', 0), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE), gc.KeyTuple('flow_level', 0)]
				)],
				[self.flow_state_update1_table.make_data(
					[],
					self.action_fstate1_read
				)]
			)
			self.flow_state_update1_table.entry_add(
				self.target,
				[self.flow_state_update1_table.make_key(
					[  gc.KeyTuple('cur_flow_time_window', 1), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE), gc.KeyTuple('flow_level', 0)]
				)],
				[self.flow_state_update1_table.make_data(
					[],
					self.action_fstate1_read
				)]
			)
			self.flow_state_update1_table.entry_add(
				self.target,
				[self.flow_state_update1_table.make_key(
					[  gc.KeyTuple('cur_flow_time_window', 1), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE), gc.KeyTuple('flow_level', 0)]
				)],
				[self.flow_state_update1_table.make_data(
					[],
					self.action_fstate1_update
				)]
			)
			self.flow_state_update2_table.entry_add(
				self.target,
				[self.flow_state_update2_table.make_key(
					[  gc.KeyTuple('cur_flow_time_window', 1), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE), gc.KeyTuple('flow_level', 0)]
				)],
				[self.flow_state_update2_table.make_data(
					[],
					self.action_fstate2_plus
				)]
			)
			self.flow_state_update2_table.entry_add(
				self.target,
				[self.flow_state_update2_table.make_key(
					[  gc.KeyTuple('cur_flow_time_window', 1), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE), gc.KeyTuple('flow_level', 0)]
				)],
				[self.flow_state_update2_table.make_data(
					[],
					self.action_fstate2_read
				)]
			)
			self.flow_state_update2_table.entry_add(
				self.target,
				[self.flow_state_update2_table.make_key(
					[  gc.KeyTuple('cur_flow_time_window', 0), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE), gc.KeyTuple('flow_level', 0)]
				)],
				[self.flow_state_update2_table.make_data(
					[],
					self.action_fstate2_read
				)]
			)
			self.flow_state_update2_table.entry_add(
				self.target,
				[self.flow_state_update2_table.make_key(
					[  gc.KeyTuple('cur_flow_time_window', 0), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_CROSSFIRE), gc.KeyTuple('flow_level', 0)]
				)],
				[self.flow_state_update2_table.make_data(
					[],
					self.action_fstate2_update
				)]
			)
			self.flow_state_update1_table.entry_add(
				self.target,
				[self.flow_state_update1_table.make_key(
					[  gc.KeyTuple('cur_flow_time_window', 0), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 0)]
				)],
				[self.flow_state_update1_table.make_data(
					[],
					self.action_fstate1_plus
				)]
			)
			self.flow_state_update1_table.entry_add(
				self.target,
				[self.flow_state_update1_table.make_key(
					[  gc.KeyTuple('cur_flow_time_window', 0), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 0)]
				)],
				[self.flow_state_update1_table.make_data(
					[],
					self.action_fstate1_read
				)]
			)
			self.flow_state_update1_table.entry_add(
				self.target,
				[self.flow_state_update1_table.make_key(
					[  gc.KeyTuple('cur_flow_time_window', 1), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 0)]
				)],
				[self.flow_state_update1_table.make_data(
					[],
					self.action_fstate1_read
				)]
			)
			self.flow_state_update1_table.entry_add(
				self.target,
				[self.flow_state_update1_table.make_key(
					[  gc.KeyTuple('cur_flow_time_window', 1), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 0)]
				)],
				[self.flow_state_update1_table.make_data(
					[],
					self.action_fstate1_update
				)]
			)
			self.flow_state_update2_table.entry_add(
				self.target,
				[self.flow_state_update2_table.make_key(
					[  gc.KeyTuple('cur_flow_time_window', 1), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 0)]
				)],
				[self.flow_state_update2_table.make_data(
					[],
					self.action_fstate2_plus
				)]
			)
			self.flow_state_update2_table.entry_add(
				self.target,
				[self.flow_state_update2_table.make_key(
					[  gc.KeyTuple('cur_flow_time_window', 1), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 0)]
				)],
				[self.flow_state_update2_table.make_data(
					[],
					self.action_fstate2_read
				)]
			)
			self.flow_state_update2_table.entry_add(
				self.target,
				[self.flow_state_update2_table.make_key(
					[  gc.KeyTuple('cur_flow_time_window', 0), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 0)]
				)],
				[self.flow_state_update2_table.make_data(
					[],
					self.action_fstate2_read
				)]
			)
			self.flow_state_update2_table.entry_add(
				self.target,
				[self.flow_state_update2_table.make_key(
					[  gc.KeyTuple('cur_flow_time_window', 0), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 0)]
				)],
				[self.flow_state_update2_table.make_data(
					[],
					self.action_fstate2_update
				)]
			)
			self.flow_state_update1_table.entry_add(
				self.target,
				[self.flow_state_update1_table.make_key(
					[  gc.KeyTuple('cur_flow_time_window', 0), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 1)]
				)],
				[self.flow_state_update1_table.make_data(
					[],
					self.action_fstate1_plus
				)]
			)
			self.flow_state_update1_table.entry_add(
				self.target,
				[self.flow_state_update1_table.make_key(
					[  gc.KeyTuple('cur_flow_time_window', 0), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 1)]
				)],
				[self.flow_state_update1_table.make_data(
					[],
					self.action_fstate1_read
				)]
			)
			self.flow_state_update1_table.entry_add(
				self.target,
				[self.flow_state_update1_table.make_key(
					[  gc.KeyTuple('cur_flow_time_window', 1), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 1)]
				)],
				[self.flow_state_update1_table.make_data(
					[],
					self.action_fstate1_read
				)]
			)
			self.flow_state_update1_table.entry_add(
				self.target,
				[self.flow_state_update1_table.make_key(
					[  gc.KeyTuple('cur_flow_time_window', 1), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 1)]
				)],
				[self.flow_state_update1_table.make_data(
					[],
					self.action_fstate1_update
				)]
			)
			self.flow_state_update2_table.entry_add(
				self.target,
				[self.flow_state_update2_table.make_key(
					[  gc.KeyTuple('cur_flow_time_window', 1), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 1)]
				)],
				[self.flow_state_update2_table.make_data(
					[],
					self.action_fstate2_plus
				)]
			)
			self.flow_state_update2_table.entry_add(
				self.target,
				[self.flow_state_update2_table.make_key(
					[  gc.KeyTuple('cur_flow_time_window', 1), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 1)]
				)],
				[self.flow_state_update2_table.make_data(
					[],
					self.action_fstate2_read
				)]
			)
			self.flow_state_update2_table.entry_add(
				self.target,
				[self.flow_state_update2_table.make_key(
					[  gc.KeyTuple('cur_flow_time_window', 0), gc.KeyTuple('global_time_window', 0), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 1)]
				)],
				[self.flow_state_update2_table.make_data(
					[],
					self.action_fstate2_read
				)]
			)
			self.flow_state_update2_table.entry_add(
				self.target,
				[self.flow_state_update2_table.make_key(
					[  gc.KeyTuple('cur_flow_time_window', 0), gc.KeyTuple('global_time_window', 1), gc.KeyTuple('cur_defense_type', net_config.DEFENSETYPE_PULSING), gc.KeyTuple('flow_level', 1)]
				)],
				[self.flow_state_update2_table.make_data(
					[],
					self.action_fstate2_update
				)]
			)
			for key_1 in [0,1]:
				for key_2 in [0,1]:
					for key_3 in [0,net_config.DEFENSETYPE_CROSSFIRE, net_config.DEFENSETYPE_COREMELT, net_config.DEFENSETYPE_PULSING]:
						for key_4 in [0,1]:
							self.flow_state_update1_table.entry_add(
								self.target,
								[self.flow_state_update1_table.make_key(
									[  gc.KeyTuple('cur_flow_time_window', key_1), gc.KeyTuple('global_time_window', key_2), gc.KeyTuple('cur_defense_type', key_3+128), gc.KeyTuple('flow_level', key_4)]
								)],
								[self.flow_state_update1_table.make_data(
									[],
									self.action_fstate1_clear
								)]
							)
			for key_1 in [0,1]:
				for key_2 in [0,1]:
					for key_3 in [0,net_config.DEFENSETYPE_CROSSFIRE, net_config.DEFENSETYPE_COREMELT, net_config.DEFENSETYPE_PULSING]:
						for key_4 in [0,1]:
							self.flow_state_update2_table.entry_add(
								self.target,
								[self.flow_state_update2_table.make_key(
									[  gc.KeyTuple('cur_flow_time_window', key_1), gc.KeyTuple('global_time_window', key_2), gc.KeyTuple('cur_defense_type', key_3+128), gc.KeyTuple('flow_level', key_4)]
								)],
								[self.flow_state_update2_table.make_data(
									[],
									self.action_fstate2_clear
								)]
							)
			for key_1 in [0,1]:
				for key_2 in [0,1]:
					for key_3 in [0,net_config.DEFENSETYPE_CROSSFIRE, net_config.DEFENSETYPE_COREMELT, net_config.DEFENSETYPE_PULSING]:
						for key_4 in [0,1]:
							self.flow_state_congestion_update1_table.entry_add(
								self.target,
								[self.flow_state_congestion_update1_table.make_key(
									[  gc.KeyTuple('cur_congestion_flow_time', key_1), gc.KeyTuple('global_congestion_time_window', key_2), gc.KeyTuple('cur_defense_type', key_3+128), gc.KeyTuple('flow_level', key_4)]
								)],
								[self.flow_state_congestion_update1_table.make_data(
									[],
									self.action_fstate1_congestion_clear
								)]
							)
			for key_1 in [0,1]:
				for key_2 in [0,1]:
					for key_3 in [0,net_config.DEFENSETYPE_CROSSFIRE, net_config.DEFENSETYPE_COREMELT, net_config.DEFENSETYPE_PULSING]:
						for key_4 in [0,1]:
							self.flow_state_congestion_update2_table.entry_add(
								self.target,
								[self.flow_state_congestion_update2_table.make_key(
									[  gc.KeyTuple('cur_congestion_flow_time', key_1), gc.KeyTuple('global_congestion_time_window', key_2), gc.KeyTuple('cur_defense_type', key_3+128), gc.KeyTuple('flow_level', key_4)]
								)],
								[self.flow_state_congestion_update2_table.make_data(
									[],
									self.action_fstate2_congestion_clear
								)]
							)
			self.get_defense_info_table.entry_add(
				self.target,
				[self.get_defense_info_table.make_key(
					[gc.KeyTuple('ig_intr_md.ingress_port', port1)]
				)],
				[self.get_defense_info_table.make_data(
					[gc.DataTuple('curv', 1), gc.DataTuple('curt', 0), gc.DataTuple('curid', net_config.sw2_id)],
					self.action_return_defense_info
				)]
			)
			
			self.get_defense_info_table.entry_add(
				self.target,
				[self.get_defense_info_table.make_key(
					[gc.KeyTuple('ig_intr_md.ingress_port', port0)]
				)],
				[self.get_defense_info_table.make_data(
					[gc.DataTuple('curv', 1), gc.DataTuple('curt', 0), gc.DataTuple('curid', net_config.sw2_id)],
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
			self.dup_filter_table.entry_add(
				self.target,
				[self.dup_filter_table.make_key(
					[gc.KeyTuple('cur_req_ver', 0)]
				)],
				[self.dup_filter_table.make_data(
					[],
					self.action_check_return0
				)]
			)
			self.dup_filter_table.entry_add(
				self.target,
				[self.dup_filter_table.make_key(
					[gc.KeyTuple('cur_req_ver', 1)]
				)],
				[self.dup_filter_table.make_data(
					[],
					self.action_check_return1
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

