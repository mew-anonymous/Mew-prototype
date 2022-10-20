from ptf import config
import ptf.testutils as testutils
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as gc
import bfrt_grpc.bfruntime_pb2 as bfruntime_pb2
import threading
import time
import datetime
from scapy.all import *
EDGE_MAC = "08:00:27:5a:18:d5"
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
cur_link_state = 0
CONGESTION_EVENT = 11
BLOCK_EVENT = 12
INITIAL_EVENT = 13
#recovery_time = 0
#congestion_time = 0
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
def synchronizing(event_type, value):
	if(event_type == CONGESTION_EVENT):
		sync_pkt = Ether(dst=EDGE_MAC)/IP(version=11, proto = int(value))
	elif(event_type == BLOCK_EVENT):
		sync_pkt = Ether(dst=EDGE_MAC)/IP(version=12, src = value)
	elif(event_type == INITIAL_EVENT):
		sync_pkt = Ether(dst=EDGE_MAC)/IP(version=13)
	sendp(sync_pkt, iface = "enp0s3")
class Defense():
	def __init__(self, name, memory, offset):
		self.name = name
		self.memory = memory
		self.offset = offset
	def set_m(self, memory):
		self.memory = memory
	def set_o(self, offset):
		self.offset = offset
class Dynamic_Reg():
	def __init__(self):
		self.users = []
		self.alloc = {}
		self.usage = 0x00000000
	def add_user(self, user):
		if(self.alloc.has_key(user.name)):
			print("already have this defense type")
			return
		else:
			if(self.usage & masklen2mask(user.memory, user.offset) == 0):
				self.users.append(user.name)
				self.alloc[user.name] = user
				return
			else:
				print("conflicted with existing users, please adjust it")
				return
	def delete_user(self, user_name):
		if(~self.alloc.has_key(user_name)):
			print("No this user")
			return
		else:
			mask_to_clear = masklen2mask(self.alloc(user_name).memory, self.alloc(user_name).offset)
			wmask = mask_to_clear ^ 0xffffffff
			self.usage = self.usage & wmask
			self.users.remove(user_name)
			self.alloc.pop(user_name, None)
class ListenswitchTest(BfRuntimeTest):
	def setUp(self):
		client_id = 0
		self.p4_name='mew_core_crossfire'
		self.table_get_defense_info='SwitchIngress.get_defense_info'
		self.action_return_defense_info='SwitchIngress.return_defense_info'
		self.table_blocktable='SwitchIngress.blocktable'
		self.action_return_block_flag='SwitchIngress.return_block_flag'
		self.table_thre_check_crossfire='SwitchIngress.thre_check_crossfire'
		self.action_upload_to_cpu_crossfire='SwitchIngress.upload_to_cpu_crossfire'
		BfRuntimeTest.setUp(self, client_id, self.p4_name)
	def initial_port_defense(self, port_id):
		self.get_defense_info_table.entry_mod(
			self.target,
			[self.get_defense_info_table.make_key(
				[gc.KeyTuple('ig_intr_md.ingress_port', port_id)]
			)],
			[self.get_defense_info_table.make_data(
				[gc.DataTuple('curv', 1), gc.DataTuple('curt', 0), gc.DataTuple('curid', 2), gc.DataTuple('is_cong', 0)],
				self.action_return_defense_info
			)]
		)
		synchronizing(INITIAL_EVENT, 0)
		print("initial_port_defense to detection", "port id:", port_id)
	def detection_thread(self, port_id):
		print("a new detection thread, port id:", port_id)
		global cur_type
		global cur_link_state
		congestion_time = 0
		recovery_time = 0
		while True:
			defense_type = 0
			self.register_table = self.bfrt_info.table_get("passing_flow_count")	
			resp = self.register_table.entry_get(
				self.target,
				[self.register_table.make_key([gc.KeyTuple('$REGISTER_INDEX', port_id)])],
				{"from_hw": True})
			for data, key in resp:
				key_value = key.to_dict()["$REGISTER_INDEX"]["value"]
				read_value = data.to_dict()["passing_flow_count.f1"]
				print("key:", key_value, "value:", read_value)
			print("passing_flow_count:", key_value, "value:", read_value[0])
			if(cur_link_state == 1):
				if(read_value > CROSSFIRE_DECT_T):
					print("Congestion and too many flows, detect CROSSFIRE")
					defense_type = 1
				ts = time.time()
				print("time:", ts)
				print("next\n")
				resp = self.get_defense_info_table.entry_get(
						self.target,
						[self.get_defense_info_table.make_key(
							[gc.KeyTuple('ig_intr_md.ingress_port', port_id)]
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
							[gc.KeyTuple('ig_intr_md.ingress_port', port_id)]
						)],
						[self.get_defense_info_table.make_data(
							[gc.DataTuple('curv', 1), gc.DataTuple('curt', defense_type), gc.DataTuple('curid', 2), gc.DataTuple('is_cong', cur_link_state)],
							self.action_return_defense_info
						)]
					)
					synchronizing(CONGESTION_EVENT, defense_type)
					cur_type = defense_type
					print("modified defense type", "port id:", port_id, "defense_type:", defense_type)
			time.sleep(0.5)
			if(cur_link_state == 1):
				congestion_time = congestion_time + 0.5
				recovery_time = 0
			elif(cur_link_state == 0):
				recovery_time = recovery_time + 0.5
				congestion_time = 0
			print("congestion_time: ", congestion_time)
			print("recovery time: ", recovery_time)
			ticks = datetime.datetime.now()
			print(ticks)
			if(recovery_time > 40 and cur_type == 1):
				print("initial the port state: ")
				self.initial_port_defense(port_id)
				cur_type = 0
	def myconnect(self):
		# Get bfrt_info and set it as part of the test
		self.bfrt_info = self.interface.bfrt_info_get(self.p4_name)
		self.target = gc.Target(device_id=0, pipe_id=0xffff)
		# get table name
		self.get_defense_info_table = self.bfrt_info.table_get(self.table_get_defense_info)
		self.blocktable_table = self.bfrt_info.table_get(self.table_blocktable)
		self.thre_check_crossfire_table = self.bfrt_info.table_get(self.table_thre_check_crossfire)
		self.thre_check_crossfire_table.entry_add(
			self.target,
			[self.thre_check_crossfire_table.make_key(
				[gc.KeyTuple('pattern_res', low=1, high=65535)]
			)],
			[self.thre_check_crossfire_table.make_data(
				[],
				self.action_upload_to_cpu_crossfire
			)]
		)
	def change_link_state(self, port_id, link_state):
		global cur_link_state
		d_t = threading.Thread(target=self.detection_thread, args=(port_id,) )
		if(link_state=='1'):
			cur_link_state = 0
		else:
			cur_link_state = 1
		if(port_id not in listen_port):
			d_t.start()
			listen_port.append(port_id)
			print("start detection thread to continously detect patterns")
		resp = self.get_defense_info_table.entry_get(
				self.target,
				[self.get_defense_info_table.make_key(
					[gc.KeyTuple('ig_intr_md.ingress_port', port_id)]
				)]
		)
		for data, key in resp:
			print("data", data.to_dict(), "key", key.to_dict())
			key_value = key.to_dict()["ig_intr_md.ingress_port"]["value"]
			defense_type_value = data.to_dict()['curt']
			is_cong_value = data.to_dict()['is_cong']
			print("key:", key_value, "is_cong:", is_cong_value, "defense_type", defense_type_value)
		if(cur_link_state!=int(is_cong_value)):
			self.get_defense_info_table.entry_mod(
				self.target,
				[self.get_defense_info_table.make_key(
					[gc.KeyTuple('ig_intr_md.ingress_port', port_id)]
				)],
				[self.get_defense_info_table.make_data(
					[gc.DataTuple('curv', 1), gc.DataTuple('curt', defense_type_value), gc.DataTuple('curid', 2), gc.DataTuple('is_cong', cur_link_state)],
					self.action_return_defense_info
				)]
			)
			print("modified link state", "port id:", port_id, "defense_type:", defense_type_value,"is_cong:", is_cong_value)
			if(cur_type == 3):
				synchronizing(CONGESTION_EVENT, 3 + cur_link_state)
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
		synchronizing(BLOCK_EVENT, str(ip_addr))
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
						temp_bin = bin(pkt[IP].ttl)
						if(temp_bin[len(temp_bin)-2]=='1'): #[1:1]
							print("link_state: Normal==>Congested") 
							self.change_link_state(pkt[IP].proto, '0')
						elif (temp_bin[len(temp_bin)-3]=='1'): #[2:2]
							print("link_state: Congested==>Normal")
							self.change_link_state(pkt[IP].proto, '1')
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

