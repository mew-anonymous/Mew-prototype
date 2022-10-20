from ptf import config
import ptf.testutils as testutils
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as gc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import threading
import time
from scapy.all import *
EDGE_MAC = "08:00:27:5a:18:d5"
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
		self.p4_name='mew_edge_crossfire'
		self.table_get_defense_info='SwitchIngress.get_defense_info'
		self.action_return_defense_info='SwitchIngress.return_defense_info'
		self.table_blocktable='SwitchIngress.blocktable'
		self.action_return_block_flag='SwitchIngress.return_block_flag'
		#self.table_extract_res='SwitchIngress.extract_res'
		#self.action_extract_coremelt='SwitchIngress.extract_coremelt'
		#self.action_extract_crossfire='SwitchIngress.extract_crossfire'
		#self.action_extract_pulsing='SwitchIngress.extract_pulsing'
		#self.action_extract_dynamic='SwitchIngress.extract_dynamic'
		#self.detection_state = Dynamic_Reg()
		#self.mitigation_state = Dynamic_Reg()
		BfRuntimeTest.setUp(self, client_id, self.p4_name)
		#self.detection_state.add_user(Defense(COREMELT, 0,0))
		#self.mitigation_state.add_user(Defense(COREMELT, 20,0))
		#self.detection_state.add_user(Defense(CROSSFIRE, 22,10))
		#self.mitigation_state.add_user(Defense(CROSSFIRE, 9,20))
		#self.detection_state.add_user(Defense(PULSING, 10,0))
		#self.mitigation_state.add_user(Defense(PULSING, 3,29))
	def myconnect(self):
		# Get bfrt_info and set it as part of the test
		self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)
		self.target = gc.Target(device_id=0, pipe_id=0xffff)
		# get table name
		self.get_defense_info_table = self.bfrt_info.table_get(self.table_get_defense_info)
		self.blocktable_table = self.bfrt_info.table_get(self.table_blocktable)
		#self.extract_res_table = self.bfrt_info.table_get(self.table_extract_res)
		#d_t = threading.Thread(target=self.detection_thread, args=(1,) )
		#print("start detection thread to continously detect patterns")
		#d_t.start()
	def change_defense_type(self, defense_type):
		global victim_state
		if(defense_type == 1):
			victim_state = 1
		resp = self.get_defense_info_table.entry_get(
					self.target,
					[self.get_defense_info_table.make_key(
						[gc.KeyTuple('ig_intr_md.ingress_port', EDGE_PORT)]
					)]
			)
		for data, key in resp:
			print("data", data.to_dict(), "key", key.to_dict())
			key_value = key.to_dict()["ig_intr_md.ingress_port"]["value"]
			read_value = data.to_dict()['curt']
			print("key:", key_value, "value:", read_value)
		if(defense_type!=int(read_value)):
			self.get_defense_info_table.entry_mod(
				self.target,
				[self.get_defense_info_table.make_key(
					[gc.KeyTuple('ig_intr_md.ingress_port', EDGE_PORT)]
				)],
				[self.get_defense_info_table.make_data(
					[gc.DataTuple('curv', 1), gc.DataTuple('curt', defense_type), gc.DataTuple('curid', 2), gc.DataTuple('is_cong', victim_state)],
					self.action_return_defense_info
				)]
			)
			print("modified defense type", "port id:", EDGE_PORT, "defense_type:", defense_type)
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
	def initial_port_defense(self, port_id):
		global cur_ver
		cur_ver = cur_ver ^ 1
		self.get_defense_info_table.entry_mod(
			self.target,
			[self.get_defense_info_table.make_key(
				[gc.KeyTuple('ig_intr_md.ingress_port', port_id)]
			)],
			[self.get_defense_info_table.make_data(
				[gc.DataTuple('curv', cur_ver), gc.DataTuple('curt', 0), gc.DataTuple('curid', 2), gc.DataTuple('is_cong', 0)],
				self.action_return_defense_info
			)]
		)
		print("initial_port_defense to detection", "port id:", port_id)
	def listen_entry(self):
		while(1):
			try:
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
			except Exception as e:
				print(e)
			
		
		
	def runTest(self):
		try:
			self.myconnect()
			self.listen_entry()
		except Exception as exc:
			print(exc)

