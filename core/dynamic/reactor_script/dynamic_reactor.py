from ptf import config
import ptf.testutils as testutils
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as gc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import threading
from scapy.all import *
link_state=[]
link_num=16
for i in range(link_num):
	link_state.append(0)
class ListenswitchTest(BfRuntimeTest):
	def setUp(self):
		client_id = 0
		self.p4_name='mew_core_dynamic'
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
		self.get_defense_info_table = self.bfrt_info.table_get(self.table_get_defense_info)
		self.blocktable_table = self.bfrt_info.table_get(self.table_blocktable)
	def change_defense(self, port_id, link_state):
		if(link_state=='1'):
			defense_type=4
		else:
			defense_type=3
		self.get_defense_info_table.entry_mod(
			self.target,
			[self.get_defense_info_table.make_key(
				[gc.KeyTuple('ig_intr_md.ingress_port', port_id)]
			)],
			[self.get_defense_info_table.make_data(
				[gc.DataTuple('curv', 1), gc.DataTuple('curt', defense_type)],
				self.action_return_defense_info
			)]
		)
		print("modified defense type", "port id:", port_id, "defense_type:", defense_type)
	def add_blocklist(self, ip_addr):
		self.blocktable_table.entry_add(
				self.target,
				[self.blocktable_table.make_key(
					[gc.KeyTuple('hdr.ipv4.src_addr', ip_addr)]
				)],
				[self.blocktable_table.make_data(
					[],
					self.action_return_block_flag
				)]
		)


	def listen_entry(self):
		while(1):
			try:
				(rcv_dev, rcv_port, rcv_pkt, pkt_time) = testutils.dp_poll(self, 0, 10)
				if(rcv_pkt!=None):
					pkt=Ether(rcv_pkt)
					print("port is", rcv_port)
					print("receive time: ",pkt_time)
					if(IP in pkt):
						print(pkt[IP].show())
						temp_bin = bin(pkt[IP].ttl)
						if(temp_bin[len(temp_bin)-2]=='1'): #[1:1]
							print("link_state: Normal==>Congested") 
							self.change_defense(pkt[IP].proto, '0')
						elif (temp_bin[len(temp_bin)-3]=='1'): #[2:2]
							print("link_state: Congested==>Normal")
							self.change_defense(pkt[IP].proto, '1')
						elif (temp_bin[len(temp_bin)-5]=='1'): #[4:4]
							print("find a suspicious IP", pkt[IP].src)
							packedIP = socket.inet_aton(pkt[IP].src)
							IP_num=struct.unpack("!L", packedIP)[0]
							print("IP address number", IP_num)
							self.add_blocklist(IP_num)
			except Exception as e:
				print(e)
			
		
		
	def runTest(self):
		try:
			self.myconnect()
			self.listen_entry()
		except Exception as exc:
			print(exc)

