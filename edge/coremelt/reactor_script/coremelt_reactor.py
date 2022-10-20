from ptf import config
import ptf.testutils as testutils
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as gc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import threading
import time
from scapy.all import *
EDGE_MAC = "08:00:27:5a:18:d5"
MY_MAC = "08:00:27:5a:18:d2"
EDGE_PORT = 0
link_state=[]
link_num=16
PORT_NUM = 512
CROSSFIRE='crossfire'
COREMELT='coremelt'
PULSING='pulsing'
CROSSFIRE_DECT_T = 10
PULSING_DECT_T = 8
COREMELT_MITI_T = 2 ** 20
CROSSFIRE_MITI_T = 128
PULSING_MITI_T = 4
priority = '1'
cur_type = 0
victim_state = 0
cur_ver = 1
#add_with_return_dyn_info 1 1 0x100000 0x20000000 0x400 0x100000 0x20000000 0x400
listen_port = []
for i in range(link_num):
	link_state.append(0)
def masklen2mask(length, offset_length):
	value = 2 ** length - 1
	value = value * 2 ** offset_length
	return value
def phy2vir(value, length, offset):
	value = value & masklen2mask(length, offset)
	value = value >> offset
	return value
class ListenswitchTest(BfRuntimeTest):
	def setUp(self):
		client_id = 0
		self.p4_name='mew_edge_coremelt'
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
		print("add a suspicious ip to blocktable", "src_addr:", ip_addr)
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
						packedIP = socket.inet_aton(pkt[IP].src)
						IP_num=struct.unpack("!L", packedIP)[0]
						self.add_blocklist(IP_num)
			except Exception as e:
				print(e)
	def listen_blocklist(self, port_id):
		print("begin to listen blocklist")
		while(1):
			rec = sniff(iface="enp0s3", count = 1, filter="inbound")
			if(IP in rec[0]):
				if(rec[0][IP].version==11):
					print(rec[0].show())
					self.change_defense_type(rec[0][IP].proto)
				elif(rec[0][IP].version==12):
					print(rec[0].show())
					packedIP = socket.inet_aton(rec[0][IP].src)
					IP_num=struct.unpack("!L", packedIP)[0]
					self.add_blocklist(IP_num)
				elif(rec[0][IP].version==13):
					print(rec[0].show())
					self.initial_port_defense(0)
		
	def runTest(self):
		try:
			self.myconnect()
			d_t = threading.Thread(target=self.listen_blocklist, args=(0,) )
			d_t.start()
			self.listen_entry()
		except Exception as exc:
			print(exc)

