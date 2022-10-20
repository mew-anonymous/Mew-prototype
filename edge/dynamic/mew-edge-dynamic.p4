/* -*- P4_16 -*- */
#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "../../common/headers.p4"
#include "../../common/util.p4"
#include "../../common/param.p4"

/*************************************************************************
*********************** T Y P E D E F  ***********************************
*************************************************************************/
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
#if __TARGET_TOFINO__ == 1
typedef bit<3> mirror_type_t;
#else
typedef bit<4> mirror_type_t;
#endif
typedef bit<8>  pkt_type_t;
const pkt_type_t PKT_TYPE_NORMAL = 1;
const pkt_type_t PKT_TYPE_MIRROR = 2;
const mirror_type_t MIRROR_TYPE_I2E = 1;
const mirror_type_t MIRROR_TYPE_E2E = 2;
const bit<8> my_swid = 1;
const bit<1> edge_flag = 1;

/*************************************************************************
*********************** C O N S T  ***********************************
*************************************************************************/
const bit<32> NUM_RAND1 = 51646229;         // A random prime number used in hash to create diff index
const bit<32> NUM_RAND2 = 122420729;        // A random prime number used in hash to create diff index


/*************************************************************************
*********************** R E G I S T E R  ***********************************
*************************************************************************/
//only for the edge switch
Register<bit<1>, bit<32>>(32w524288,0) existing_state;
Register<bit<1>, bit<32>>(32w524288,0) request_version;
Register<bit<1>, bit<32>>(32w524288,0) flow_time_window;
Register<bit<1>, bit<32>>(32w524288,0) congestion_flow_time_window;
Register<bit<1>, bit<32>>(32w524288,0) link_time_window;
Register<bit<1>, bit<32>>(32w140000,0) below_threshold;
Register<bit<1>, bit<32>>(32w140000,0) exceed_threshold;
Register<bit<8>, bit<32>>(32w524288,0) flow_bigtime;
Register<bit<32>, bit<32>>(32w1) my_load;

Register<bit<8>, bit<32>>(32w524288) flow_ds_depth;   //CMS, the stored number may be big, should we only use it for modification stage. Normally, use table action to store depth

//flowsz/flow_rate
Register<bit<32>, bit<32>>(32w140000) flowrate1;
Register<bit<32>, bit<32>>(32w140000) flowrate2;

//pulsing
Register<bit<32>, bit<32>>(32w140000) flowrate1_congestion;
Register<bit<32>, bit<32>>(32w140000) flowrate2_congestion;
//coremelt
Register<bit<32>, bit<32>>(32w140000) reduce_flowrate1;
Register<bit<32>, bit<32>>(32w140000) reduce_flowrate2;
//crossfire
Register<bit<16>, bit<32>>(32w140000) lowrate_flow_num1;
Register<bit<16>, bit<32>>(32w140000) lowrate_flow_num2;

//dynamic
Register<bit<64>, bit<32>>(32w70000) dynamic_state1;
Register<bit<64>, bit<32>>(32w70000) dynamic_state2;
//link utilization
Register<bit<32>, bit<16>>(32w1024) linkrate1;
Register<bit<32>, bit<16>>(32w1024) linkrate2;

//blocklist
//Register<bit<32>, bit<32>>(32w1024) queue_suspicious;
Register<bit<1>, bit<32>>(32w1048576, 0) suspicious_list;




/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/



header sel_t{ //ip.version = 4+2
	bit<8> depth;
	bit<8> edge_id;
	bit<8> passing_depth;
	bit<8> padding;
	bit<32> sw_load;
}
header monitor_t{ //ip.version = 4+1
	bit<32> depth;
}
header statem_t{ //ip.version = 4+4
	bit<8> depth;
	bit<8> cache_depth;
	bit<32> flow_rate1;
	bit<32> flow_rate2;
	bit<32> flow_rate3;
	bit<32> flow_rate4;
}
header seldone_t{ //ip.version = 4+3
	bit<8> depth;
	bit<8> edge_id;
}
header layer4_t{
    bit<16> src_port;
    bit<16> dst_port;
}
header cd_t{ //ip.version = 4+5
	bit<8> defense_version;
	bit<1> hit;  //is it filled?
	bit<7> req_id;
	bit<32> state1;
}

header mirror_h {
    pkt_type_t  pkt_type;
	bit<8> depth;
	bit<8> edge_id;
}

header bridge_md_t{
bit<8> cur_id;
bit<8> filter;     //0:in blocklist; 1:captured by itself; 2:from outside; 3:output outside; 4: a new flow; 5: in cache 6: remove the extra header 7:mirror to edge switch
bit<16> cur_port;
bit<32> flowkey;
bit<32> cur_load;
bit<32> r_flowkey;
//bit<32> cur_port_ts;
}
struct metadata_t {
//new_proc_param_pos
    /* empty */
    pkt_type_t pkt_type;
	bit<8> depth;
	bit<8> edge_id;
	bit<8> protocol;
}

struct headers {
    ethernet_h   ethernet;
	vlan_tag_h	vlan_tag;
    ipv4_h      ipv4;
	monitor_t    monitor;
    sel_t        sel;
	seldone_t    seldone;
	statem_t      statem;
    cd_t 	 cd;
	layer4_t layer4;
//add_headers_pos
}
/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser SwitchIngressParser(
        packet_in pkt,
        out headers hdr,
        out metadata_t meta,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }
	state parse_ethernet{
		pkt.extract(hdr.ethernet);
		transition select(hdr.ethernet.ether_type){
			0x800: parse_ipv4;
			0x8100: parse_vlan;
			default: accept;
		}
	}
	state parse_vlan{
		pkt.extract(hdr.vlan_tag);
		transition select(hdr.vlan_tag.ether_type){
			0x800: parse_ipv4;
			default: accept;
		}
			
	}
	state parse_ipv4{
		pkt.extract(hdr.ipv4);
		meta.protocol=hdr.ipv4.protocol;
		transition select(hdr.ipv4.version){
			IPTYPE_IPV4:    parse_pre_layer4;
			IPTYPE_MONITOR:    parse_monitor;
			IPTYPE_SEL:    parse_sel;
			IPTYPE_SELDONE:    parse_seldone;
			IPTYPE_STATEM:    parse_statem;
			IPTYPE_CD:    parse_cd;
			default:		reject;
		}
    }
    state parse_monitor{
        pkt.extract(hdr.monitor);
		transition parse_pre_layer4;
    }
    state parse_sel{
		pkt.extract(hdr.sel);
		transition parse_pre_layer4;
    }
    state parse_seldone{
		pkt.extract(hdr.seldone);
		transition parse_pre_layer4;
    }
    state parse_statem{
		pkt.extract(hdr.statem);
		transition parse_pre_layer4;
    }
    state parse_cd{
        pkt.extract(hdr.monitor);
		pkt.extract(hdr.cd);
		transition parse_pre_layer4;
    }
	state parse_pre_layer4{
        transition select(meta.protocol){
			IP_PROTOCOLS_TCP: parse_layer4;
			IP_PROTOCOLS_UDP: parse_layer4;
			default: accept;
		}
    }
    state parse_layer4{
        pkt.extract(hdr.layer4);
        transition accept;
    }
}


control SwitchIngressDeparser(
        packet_out pkt,
        inout headers hdr,
        in metadata_t meta,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
         pkt.emit(hdr);
    }
}
/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control SwitchIngress(
        inout headers hdr,
        inout metadata_t meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
	bit<1> local_hit = 0;
	bit<1> is_blocked = 0;
	bit<1> is_new_window= 0;
	bit<1> is_congestion = 0;
	bit<1> blocklist_update = 0;
	bit<1> old_blockstate = 0;
	bit<1> filter_idx = 0;
	bit<1> is_incache = 0;
	bit<1> last_hop = 0;
	bit<1> stale_flag = 0;
	bit<1> select_flag = 0;
	bit<1> existing_flag = 0;
	bit<8> last_time = 0;
	bit<8> cur_big_time = 0;
	bit<1> being_congested = 0;
	bit<1> being_requested = 0;
	bit<1> cache_monitor_flag = 0;
	bit<1> flow_monitor_flag = 0;
	bit<2> cur_cache_flag = 0;
	bit<1> global_time_window = 0;
	bit<1> cur_flow_time_window = 0;
	bit<1> cur_cache_time_window = 0;
	bit<1> cur_link_time_window = 0;
	bit<1> my_load_flag = 0;
	bit<2> local_state_flag = 0;
	bit<8> depth_to_update = 0;
	bit<8> depth_get = 0;
	bit<1> flow_ds_depth_flag = 0;
	bit<32> flowkey_5tuple = 0;
	bit<32> flowkey_2tuple = 0;
	bit<32> record_key = 0;
	bit<32> dup_filter_key = 0;
	bit<32> suspicious_key = 0;
	bit<32> flow_ds_depth_key = 0;
	bit<32> my_cache_index_update_key = 0;
	bit<32> cur_port_index = 0;
	bit<32> cur_load = 0;
	bit<32> load_to_update = 0;
	bit<32> lstate_to_update = 0;
	bit<32> fstate1_to_update = 0;
	bit<32> fstate2_to_update = 0;
	bit<32> f_r_state1_to_update = 0;
	bit<32> f_r_state2_to_update = 0;
	bit<32> fstate3_to_update = 0;
	bit<32> fstate4_to_update = 0;
	bit<32> cache1_value = 0;
	bit<32> cache2_value = 0;
	bit<32> cache3_value = 0;
	bit<16> cur_cache_index = 0;
	bit<32> cur_cache_index32 = 0;
	bit<32> fcache_state1 = 0;
	bit<32> fcache_state2 = 0;
	bit<32> fcache_state3 = 0;
	bit<32> flow_state = 0;
	bit<32> congestion_flow_state = 0;
	bit<32> link_state = 0;
	bit<2> link_update_version = 0;
	bit<1> flow_update_version = 0;
	bit<1> cache_update_version = 0;
	bit<8> state2_update_version = 0;
	bit<32> flowstate2_to_update = 0;
	bit<32> flow2_state = 0;
	bit<1> cur_req_ver = 0;
	bit<1> has_returned = 0;
	bit<8> cur_defense_type = 0;
	bit<7> cur_req_id = 0;
	bit<16> flow_num = 0;
	bit<32> pulsing_flag = 0;
	bit<1> flow_level = 0;
	bit<1> global_congestion_time_window = 0;
	bit<1> cur_congestion_flow_time = 0;
	bit<1> global_flow_time_window = 0;
	bit<1> migrate_flag = 0;
	//request_version_flow
	RegisterAction<bit<1>, bit<32>, bit<1>>(request_version) req_ver_1 = {
        void apply(inout bit<1> value, out bit<1> read_value){
				read_value = value;  //return 1 if inconsistent
				value = 1;
		}
    };
	RegisterAction<bit<1>, bit<32>, bit<1>>(request_version) req_ver_0 = {
        void apply(inout bit<1> value, out bit<1> read_value){
				read_value = value;  //return 1 if inconsistent
				value = 0;
		}
    };	
	//suspicious_list 
	RegisterAction<bit<1>, bit<32>, bit<1>>(suspicious_list) suspicious_r = {
        void apply(inout bit<1> value, out bit<1> read_value){
            read_value = value;
        }
    };	
	RegisterAction<bit<1>, bit<32>, bit<1>>(suspicious_list) suspicious_w = {
        void apply(inout bit<1> value, out bit<1> read_value){
			read_value = value;
			value = 1;
        }
    };
	RegisterAction<bit<1>, bit<32>, bit<1>>(suspicious_list) suspicious_c = {
        void apply(inout bit<1> value, out bit<1> read_value){
			read_value = value;
			value = 0;
        }
    };
	//my_load
	RegisterAction<bit<32>, bit<32>, bit<32>>(my_load) my_load_read = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
        }
    };
	RegisterAction<bit<32>, bit<32>, bit<32>>(my_load) my_load_plus = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
			value = value + 1;
        }
    };
	RegisterAction<bit<32>, bit<32>, bit<32>>(my_load) my_load_update = {
        void apply(inout bit<32> value, out bit<32> read_value){
			value = 1;//load_to_update;
        }
    };
	//existing state 
	RegisterAction<bit<1>, bit<32>, bit<1>>(existing_state) existing_state_fill_1 = {
        void apply(inout bit<1> value, out bit<1> read_value){
			read_value = value;
			value =1; 
        }
    };
	RegisterAction<bit<1>, bit<32>, bit<1>>(existing_state) existing_state_fill_0 = {
        void apply(inout bit<1> value, out bit<1> read_value){
			read_value = value;
			value =0; 
        }
    };
	RegisterAction<bit<1>, bit<32>, bit<1>>(existing_state) existing_state_read = {
        void apply(inout bit<1> value, out bit<1> read_value){
			read_value = value;
        }
    };
	
	//pulsing state
	RegisterAction<bit<1>, bit<32>, bit<1>>(below_threshold) below_threshold_fill = {
        void apply(inout bit<1> value, out bit<1> read_value){
			read_value = value;
			value =1; 
        }
    };
	RegisterAction<bit<1>, bit<32>, bit<1>>(below_threshold) below_threshold_read = {
        void apply(inout bit<1> value, out bit<1> read_value){
			read_value = value;
        }
    };
	RegisterAction<bit<1>, bit<32>, bit<1>>(exceed_threshold) exceed_threshold_fill = {
        void apply(inout bit<1> value, out bit<1> read_value){
			read_value = value;
			value =1; 
        }
    };
	RegisterAction<bit<1>, bit<32>, bit<1>>(exceed_threshold) exceed_threshold_read = {
        void apply(inout bit<1> value, out bit<1> read_value){
			read_value = value;
        }
    };
	
	RegisterAction<bit<1>, bit<32>, bit<1>>(flow_time_window) flow_time_fill_1 = {
        void apply(inout bit<1> value, out bit<1> read_value){
			read_value = value;
			value = 1; 
        }
    };	
	RegisterAction<bit<1>, bit<32>, bit<1>>(flow_time_window) flow_time_fill_0 = {
        void apply(inout bit<1> value, out bit<1> read_value){
			read_value = value;
			value = 0; 
        }
    };
	RegisterAction<bit<1>, bit<32>, bit<1>>(congestion_flow_time_window) congestion_flow_time_fill_1 = {
        void apply(inout bit<1> value, out bit<1> read_value){
			read_value = value;
			value = 1; 
        }
    };	
	RegisterAction<bit<1>, bit<32>, bit<1>>(congestion_flow_time_window) congestion_flow_time_fill_0 = {
        void apply(inout bit<1> value, out bit<1> read_value){
			read_value = value;
			value = 0; 
        }
    };
	/*RegisterAction<bit<8>, bit<32>, bit<8>>(flow_bigtime) flow_bigtime_update = {
        void apply(inout bit<8> value, out bit<8> read_value){
			read_value = value;
			value = cur_big_time; 
        }
    };*/
	
	//flowrate 
	RegisterAction<bit<32>, bit<32>, bit<32>>(flowrate1) flowrate1_update = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
			value = fstate1_to_update;  
        }
    };
	RegisterAction<bit<32>, bit<32>, bit<32>>(flowrate1) flowrate1_plus = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
			value = value + fstate1_to_update;  
        }
    };
	RegisterAction<bit<32>, bit<32>, bit<32>>(flowrate1) flowrate1_read = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
        }
    };
	RegisterAction<bit<32>, bit<32>, bit<32>>(flowrate1) flowrate1_clear = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
			value = 0;
        }
    }; 
	RegisterAction<bit<32>, bit<32>, bit<32>>(flowrate2) flowrate2_update = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
			value = fstate2_to_update;  
        }
    };
	RegisterAction<bit<32>, bit<32>, bit<32>>(flowrate2) flowrate2_plus = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
			value = value + fstate2_to_update;  
        }
    };
	RegisterAction<bit<32>, bit<32>, bit<32>>(flowrate2) flowrate2_read = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
        }
    };
	RegisterAction<bit<32>, bit<32>, bit<32>>(flowrate2) flowrate2_clear = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
			value = 0;
        }
    }; 
	
	RegisterAction<bit<32>, bit<32>, bit<32>>(flowrate1_congestion) flowrate1_congestion_update = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
			value = fstate1_to_update;  
        }
    };
	RegisterAction<bit<32>, bit<32>, bit<32>>(flowrate1_congestion) flowrate1_congestion_plus = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
			value = value + fstate1_to_update;  
        }
    };
	RegisterAction<bit<32>, bit<32>, bit<32>>(flowrate1_congestion) flowrate1_congestion_read = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
        }
    };
	RegisterAction<bit<32>, bit<32>, bit<32>>(flowrate1_congestion) flowrate1_congestion_clear = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
			value = 0;
        }
    }; 
	RegisterAction<bit<32>, bit<32>, bit<32>>(flowrate2_congestion) flowrate2_congestion_update = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
			value = fstate2_to_update;  
        }
    };
	RegisterAction<bit<32>, bit<32>, bit<32>>(flowrate2_congestion) flowrate2_congestion_plus = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
			value = value + fstate2_to_update;  
        }
    };
	RegisterAction<bit<32>, bit<32>, bit<32>>(flowrate2_congestion) flowrate2_congestion_read = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
        }
    };
	RegisterAction<bit<32>, bit<32>, bit<32>>(flowrate2_congestion) flowrate2_congestion_clear = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
			value = 0;
        }
    }; 
	
	//link_load
	RegisterAction<bit<1>, bit<32>, bit<1>>(link_time_window) link_time_fill_1 = {
        void apply(inout bit<1> value, out bit<1> read_value){
			read_value = value;
			value = 1; 
        }
    };	
	RegisterAction<bit<1>, bit<32>, bit<1>>(link_time_window) link_time_fill_0 = {
        void apply(inout bit<1> value, out bit<1> read_value){
			read_value = value;
			value = 0; 
        }
    };
	RegisterAction<bit<32>, bit<32>, bit<32>>(linkrate1) linkrate1_update = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
			value = lstate_to_update;  
        }
    };
	RegisterAction<bit<32>, bit<32>, bit<32>>(linkrate1) linkrate1_plus = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
			value = value + lstate_to_update;  
        }
    };
	RegisterAction<bit<32>, bit<32>, bit<32>>(linkrate1) linkrate1_read = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
        }
    };
	RegisterAction<bit<32>, bit<32>, bit<32>>(linkrate1) linkrate1_clear = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
			value = 0;
        }
    };
	RegisterAction<bit<32>, bit<32>, bit<32>>(linkrate2) linkrate2_update = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
			value = lstate_to_update;  
        }
    };
	RegisterAction<bit<32>, bit<32>, bit<32>>(linkrate2) linkrate2_plus = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
			value = value + lstate_to_update;  
        }
    };
	RegisterAction<bit<32>, bit<32>, bit<32>>(linkrate2) linkrate2_read = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
        }
    };
	RegisterAction<bit<32>, bit<32>, bit<32>>(linkrate2) linkrate2_clear = {
        void apply(inout bit<32> value, out bit<32> read_value){
			read_value = value;
			value = 0;
        }
    };
	
	
	RegisterAction<bit<8>, bit<32>, bit<8>>(flow_ds_depth) flow_ds_depth_read = {
        void apply(inout bit<8> value, out bit<8> read_value){
			read_value = value;
        }
    };
	RegisterAction<bit<8>, bit<32>, bit<8>>(flow_ds_depth) flow_ds_depth_update = {
        void apply(inout bit<8> value, out bit<8> read_value){
			value = depth_to_update;
        }
    };
	
	action remove_vlan(PortId_t dst_port, bit<48> dst_addr) {
        ig_tm_md.ucast_egress_port = dst_port;
		hdr.ethernet.src_addr=hdr.ethernet.dst_addr;
		hdr.ethernet.dst_addr=dst_addr;
		last_hop = 1;
    }

    action route_nat(PortId_t dst_port, bit<48> dst_addr) {
        ig_tm_md.ucast_egress_port = dst_port;
		hdr.vlan_tag.vid = 1;   //internal packet
		hdr.ethernet.src_addr=hdr.ethernet.dst_addr;
		hdr.ethernet.dst_addr=dst_addr;
    }
	
	table all_route {
        key = {
			ig_intr_md.ingress_port: exact;
			hdr.ipv4.dst_addr: exact;
        }

        actions = {
            route_nat;
			remove_vlan;
        }
        size = 16;
    }
	
	
	

	
	
	
	/////////////flow_state//////////////////////////
		//flow_state_window1
		action fstate1_update(){ // v: 1, g,c:1/0; v: 0, g: 0, c: 1
			flowrate1_update.execute(record_key);
		}
		action fstate1_read(){   // v: 0, g: 1, c: 0/1
			flow_state = flowrate1_read.execute(record_key);//[31:16];
		}
		action fstate1_plus(){	// v: 0, g: 0, c: 0
			//fstate1_to_update[15:0] = hdr.ipv4.total_len;
			flowrate1_plus.execute(record_key);
		}
		action fstate1_clear(){	
			hdr.statem.flow_rate1 = flowrate1_clear.execute(record_key);
		}
		table flow_state_update1{
			key = {
				cur_defense_type: exact;
				cur_flow_time_window: exact;
				global_time_window: exact;
				flow_level: exact;
				//migrate_flag: exact;
			}
			
			actions = {
				fstate1_update;
				fstate1_read;
				fstate1_plus;
				fstate1_clear;
			}
			size = 64;
		}
		
		//flow_state_window2
		action fstate2_update(){	// v: 1, g,c:1/0; v: 0, g: 1, c: 0
			flowrate2_update.execute(record_key);
		}
		action fstate2_read(){		// v: 0, g: 0, c: 0/1
			flow_state = flowrate2_read.execute(record_key);//[31:16];
		}
		action fstate2_plus(){		// v: 0, g: 1, c: 1
			flowrate2_plus.execute(record_key);
		}
		action fstate2_clear(){
			hdr.statem.flow_rate2 = flowrate2_clear.execute(record_key);
		}
		table flow_state_update2{
			key = {
				cur_defense_type: exact;
				cur_flow_time_window: exact;
				global_time_window: exact;
				flow_level: exact;
				//migrate_flag: exact;
			}
			
			actions = {
				fstate2_update;
				fstate2_read;
				fstate2_plus;
				fstate2_clear;
			}
			size = 64;
		}
		
		//flow_state_window1
		action fstate1_congestion_update(){ // v: 1, g,c:1/0; v: 0, g: 0, c: 1
			flowrate1_congestion_update.execute(record_key);
		}
		action fstate1_congestion_read(){   // v: 0, g: 1, c: 0/1
			congestion_flow_state = flowrate1_congestion_read.execute(record_key);//[31:16];
		}
		action fstate1_congestion_plus(){	// v: 0, g: 0, c: 0
			//fstate1_to_update[15:0] = hdr.ipv4.total_len;
			flowrate1_congestion_plus.execute(record_key);
		}
		action fstate1_congestion_clear(){	
			hdr.statem.flow_rate3 = flowrate1_congestion_clear.execute(record_key);
		}
		table flow_state_congestion_update1{
			key = {
				cur_defense_type: exact;
				cur_congestion_flow_time: exact;
				global_congestion_time_window: exact;
				flow_level: exact;
				//migrate_flag: exact;
			}
			
			actions = {
				fstate1_congestion_update;
				fstate1_congestion_read;
				fstate1_congestion_plus;
				fstate1_congestion_clear;
			}
			size = 64;
		}
		
		//flow_state_window2
		action fstate2_congestion_update(){	// v: 1, g,c:1/0; v: 0, g: 1, c: 0
			flowrate2_congestion_update.execute(record_key);
		}
		action fstate2_congestion_read(){		// v: 0, g: 0, c: 0/1
			congestion_flow_state = flowrate2_congestion_read.execute(record_key);//[31:16];
		}
		action fstate2_congestion_plus(){		// v: 0, g: 1, c: 1
			flowrate2_congestion_plus.execute(record_key);
		}
		action fstate2_congestion_clear(){
			hdr.statem.flow_rate4 = flowrate2_congestion_clear.execute(record_key);
		}
		table flow_state_congestion_update2{
			key = {
				cur_defense_type: exact;
				cur_congestion_flow_time: exact;
				global_congestion_time_window: exact;
				flow_level: exact;
				//migrate_flag: exact;
			}
			
			actions = {
				fstate2_congestion_update;
				fstate2_congestion_read;
				fstate2_congestion_plus;
				fstate2_congestion_clear;
			}
			size = 64;
		}
	
	/////////////flow_state//////////////////////////
	
	/////////////link_state//////////////////////////
		//link_state_window1
		action lstate1_update(){
			is_new_window=1;
			linkrate1_update.execute(cur_port_index);
		}
		action lstate1_read(){
			link_state = linkrate1_read.execute(cur_port_index);
		}
		action lstate1_plus(){
			linkrate1_plus.execute(cur_port_index);
		}
		action lstate1_clear(){
			linkrate1_clear.execute(cur_port_index);
		}
		
		table link_state_update1{
			key = {
				cur_link_time_window: exact;
				global_time_window: exact;
			}
			
			actions = {
				lstate1_update;
				lstate1_read;
				lstate1_plus;
				lstate1_clear;
			}
			size = 4;
		}
		
		//link_state_window2
		action lstate2_update(){
			is_new_window=1;
			linkrate2_update.execute(cur_port_index);
		}
		action lstate2_read(){
			link_state = linkrate2_read.execute(cur_port_index);
		}
		action lstate2_plus(){
			linkrate2_plus.execute(cur_port_index);
		}
		action lstate2_clear(){
			linkrate2_clear.execute(cur_port_index);
		}
		table link_state_update2{
			key = {
				cur_link_time_window: exact;
				global_time_window: exact;
			}
			
			actions = {
				lstate2_update;
				lstate2_read;
				lstate2_plus;
				lstate2_clear;
			}
			size = 4;
		}
		
		
	/////////////link_state//////////////////////////
	
	
	
	action return_defense_info(bit<1> curv, bit<8> curt, bit<7> curid, bit<1> is_cong){
		//being_congested = 1;
		cur_req_ver = curv;
		cur_defense_type = curt;   //coremelt
		cur_req_id = curid;   //coremelt
		is_congestion = is_cong;
	}
	table get_defense_info{
		key = {
			ig_intr_md.ingress_port: exact;
		}
		actions = {
			return_defense_info;
		}
		size = 2;
	}
	action my_drop(){
		ig_tm_md.ucast_egress_port = 10;
	}

	CRCPolynomial<bit<32>>(32w0x04C11DB7, // polynomial
                           true,          // reversed
                           false,         // use msb?
                           false,         // extended?
                           32w0xFFFFFFFF, // initial shift register value
                           32w0xFFFFFFFF  // result xor
                           ) poly1;
    Hash<bit<19>>(HashAlgorithm_t.CUSTOM, poly1) hash1;
    Hash<bit<20>>(HashAlgorithm_t.CUSTOM, poly1) hash2;
	action return_block_flag(){
		is_blocked = 1;
		ig_dprsr_md.drop_ctl = 1; // Drop packet.
	}
	table blocktable{
		key = {
			hdr.ipv4.src_addr: exact;
		}
		actions = {
			return_block_flag;
		}
	}
	action return_stale(){
		stale_flag = 1;
	}
	table stale_test{
		key = {
			last_time: exact;
		}
		actions = {
			return_stale;
		}
	}
	action upload_to_cpu_coremelt(bit<9> dst_port){
		ig_tm_md.ucast_egress_port = dst_port;
		hdr.ipv4.version = 11;  //a special packet for banning a flow
	}
	action drop_coremelt(){
		ig_dprsr_md.drop_ctl = 1; // Drop packet.
	}
	table inform_others{
		key = {
			blocklist_update: exact;
		}
		actions = {
			upload_to_cpu_coremelt;
			drop_coremelt;
		}
	}
	action update_blocklist(){
		blocklist_update = 1;
		old_blockstate = suspicious_w.execute(flowkey_2tuple);
	}
	table thre_check_crossfire{
		key = {
			flow_num : range;
		}
		actions = {
			update_blocklist;
		}
	}
	action check_return1(){
		has_returned = req_ver_1.execute(flowkey_5tuple) + cur_req_ver;;
	}
	action check_return0(){
		has_returned = req_ver_0.execute(flowkey_5tuple) + cur_req_ver;;
	}
	table dup_filter{
		key = {
			cur_req_ver: exact;
		}
		actions = {
			check_return0;
			check_return1;
		}
		size = 16;
	}
	action eight_second(){  //normal mode
		global_time_window = ig_prsr_md.global_tstamp[33:33];
	}
	action one_second(){  //normal mode
		global_time_window = ig_prsr_md.global_tstamp[30:30];
	}
	action one_msecond(){ //sensitive mode
		global_time_window = ig_prsr_md.global_tstamp[20:20];
	}
	table get_time_window{
		actions = {
			eight_second;
			one_second;
			one_msecond;
		}
		default_action = one_second();
		size = 32;
	}
	action normal_window(){  //normal mode
		global_flow_time_window = ig_prsr_md.global_tstamp[34:34];
	}
	table get_flow_time_window{
		actions = {
			normal_window;
		}
		default_action = normal_window();
		size = 1;
	}
	action pulsing_1s(){  //sensitive mode
		global_congestion_time_window = ig_prsr_md.global_tstamp[30:30];  
	}
	action normal_8s(){  //normal mode
		global_congestion_time_window = ig_prsr_md.global_tstamp[33:33];  
	}
	table get_congestion_time_window{
		actions = {
			pulsing_1s;
			normal_8s;
		}
		default_action = pulsing_1s();
		size = 32;
	}
	action flow_time1(){
		cur_flow_time_window = flow_time_fill_1.execute(flowkey_5tuple);
	}
	action flow_time0(){
		cur_flow_time_window = flow_time_fill_0.execute(flowkey_5tuple);
	}
	table flow_time_update {
		key = {
			global_flow_time_window: exact;
		}
		actions = {
			flow_time1;
			flow_time0;
		}
	}
	action congestion_flow_time1(){
		cur_congestion_flow_time = congestion_flow_time_fill_1.execute(flowkey_5tuple);
	}
	action congestion_flow_time0(){
		cur_congestion_flow_time = congestion_flow_time_fill_0.execute(flowkey_5tuple);
	}
	table congestion_flow_time_update {
		key = {
			global_congestion_time_window: exact;
		}
		actions = {
			congestion_flow_time1;
			congestion_flow_time0;
		}
	}
    apply {
		ig_tm_md.bypass_egress = 1w1;
		@stage(0){
			get_time_window.apply();
			global_congestion_time_window = ig_prsr_md.global_tstamp[30:30]; 
			//cur_big_time = ig_prsr_md.global_tstamp[39:32]; 
			cur_port_index[8:0] = ig_intr_md.ingress_port;
			get_defense_info.apply();
			blocktable.apply();
			flowkey_5tuple[18:0] = hash1.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.layer4.src_port, hdr.layer4.dst_port, hdr.ipv4.protocol});
			fstate1_to_update[15:0] = hdr.ipv4.total_len;
			fstate2_to_update[15:0] = hdr.ipv4.total_len;
			lstate_to_update[15:0] = hdr.ipv4.total_len;
			all_route.apply();   //get next hop for different kinds of packets
		}
		if(is_blocked == 0){ 
			@stage(1){
				if(global_time_window==0)
					cur_link_time_window = link_time_fill_0.execute(cur_port_index);
				else
					cur_link_time_window = link_time_fill_1.execute(cur_port_index);
				existing_flag = existing_state_fill_1.execute(flowkey_5tuple);
				if(cur_defense_type != 3){
					global_congestion_time_window = global_time_window;
				}
				
				//last_time = flow_bigtime_update.execute(flowkey_5tuple);   //47:32, 16 bit, value = per 4 second, time = cur_big_time
				record_key[16:0] = flowkey_5tuple[16:0]; 
				flow_level = flowkey_5tuple[17:17];
			}
			if(hdr.ipv4.isValid()){
				@stage(2){
					if(hdr.ipv4.version == 7){  //seldone packet --> statem; drop; 
						depth_to_update = hdr.seldone.depth;
						flow_ds_depth_flag = 1;  
						if(hdr.seldone.depth == 1) //this is the target, drop the packet and record the flow
						{
							my_load_flag = 1; 
							ig_dprsr_md.drop_ctl = 1; 
						}
						else{
							flow_monitor_flag = 1;
							cur_defense_type = cur_defense_type | 0x80;
							hdr.statem.setValid();
							hdr.ipv4.version = 8;
							hdr.statem.depth = hdr.seldone.depth - 1;
							hdr.seldone.setInvalid();
							ig_tm_md.ucast_egress_port = 1;
						}
					}
					//else if(hdr.ipv4.version == 4 && last_hop != 1 && existing_flag!=1){
					//	depth_to_update = 1; //cache locally
					//	flow_ds_depth_flag = 1;
					//}
				}
				@stage(2){	
					if(hdr.ipv4.version == 4 && last_hop !=1) //a original packet 
					{
						if(existing_flag==1)// && last_time[7:3] == 0) //this is not a new flow, go to monitor 
						{
							@stage(3){
								hdr.ipv4.version = 5;
								hdr.monitor.setValid();	
							}
						}
						else    //this is a new flow, --> sel
						{
							@stage(3){
								flow_monitor_flag = 1;
								depth_to_update = 1; //cache locally
								flow_ds_depth_flag = 1;
								depth_get = 1;
								hdr.sel.setValid();
								hdr.sel.edge_id = my_swid;
								hdr.sel.passing_depth = 1; //the depth of the current switch 
								hdr.sel.depth = 1;   //the depth of current least utilized switch
								hdr.ipv4.version = 10;
							}
						}
					}
				}
				@stage(4){	
					if(flow_ds_depth_flag==0)
						depth_get = flow_ds_depth_read.execute(flowkey_5tuple);
					else
						flow_ds_depth_update.execute(flowkey_5tuple);
				}
				@stage(5){
					if(hdr.monitor.isValid()){
						hdr.monitor.depth[7:0] = depth_get - 1;
					}
				}
				@stage(5){
					if(depth_get == 1 && cur_defense_type != 2){
						flow_monitor_flag = 1;
						flow_time_update.apply();
						congestion_flow_time_update.apply();
					}
					if(hdr.ipv4.version != 8 && hdr.ipv4.version != 7)
						dup_filter.apply();
					@stage(6){
						if(has_returned == 1 && hdr.ipv4.version != 8){
							hdr.ipv4.ihl[3:3] = 1;
						}
					}
					if(my_load_flag==0){
						if(hdr.sel.isValid())
							hdr.sel.sw_load = my_load_read.execute(0);
					}
					else{
						my_load_plus.execute(0);
					}
				}
				@stage(2){
					link_state_update1.apply();
					//last_time=cur_big_time-last_time; //should be 0
				}
				@stage(3){
					link_state_update2.apply();
				}
				if(flow_monitor_flag==1 && hdr.ipv4.version != 7){
					@stage(6){
						flow_state_update1.apply();
					}
					@stage(7){
						flow_state_update2.apply();
					}
					@stage(8){
						if(cur_defense_type == 3){
							flow_state = flow_state >> 2; //window ratio/2 = 4
						}
						flow_state_congestion_update1.apply();
					}
					@stage(9){
						flow_state_congestion_update2.apply();
					}
					
				}
				if(hdr.monitor.isValid()){
					@stage(10){
						if(flow_monitor_flag==1){
							if(cur_defense_type == 3 && flow_state != 0 && is_congestion == 1){
								pulsing_flag = congestion_flow_state |-| flow_state; //saturated subtract, should be 0 if high-speed / low-speed < 16
							}
							else if(cur_defense_type == 1){
								if(flow_level == 1){
									flow_state = congestion_flow_state;
								}
							}
							cur_congestion_flow_time = global_congestion_time_window + cur_congestion_flow_time; //mask
							cur_flow_time_window = cur_flow_time_window + global_time_window; //mask
						}
					}
					@stage(11){
						if(hdr.ipv4.version == 5){ // in this window, already responded
							if(cur_defense_type == 1 || cur_defense_type == 2 || cur_defense_type == 3){
								hdr.cd.setValid();
								hdr.ipv4.version = 9;
								hdr.cd.req_id = cur_req_id;
								hdr.cd.defense_version = cur_defense_type;
								hdr.cd.hit = flow_monitor_flag;
								if(cur_flow_time_window == 1 && cur_defense_type == 1 && flow_state[31:10]==0 && flow_monitor_flag == 1) //crossfire
									hdr.cd.state1[0:0] = 1;
								else if(cur_defense_type == 3 && pulsing_flag != 0 && cur_congestion_flow_time == 1) //pulsing
									hdr.cd.state1[0:0] = 1;
							}
						}
					}
				}
			}
		}
	}
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         EmptyEgressParser(),
         EmptyEgress(),
         EmptyEgressDeparser()) pipe;

Switch(pipe) main;
