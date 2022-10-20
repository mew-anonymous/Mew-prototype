#simple topo: host--port0--edge switch--port1--port1--core switch--port0--host

#edge switch
sw1_id = 1
sw1_port0 = 0
sw1_port1 = 1
sw1_port2 = 2
sw1_port_cpu = 10
#core switch
sw2_id = 2
sw2_port0 = 0
sw2_port1 = 1
sw2_port2 = 2
sw2_port_cpu = 10
#host
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
#defense
DEFENSETYPE_CROSSFIRE = 1
DEFENSETYPE_COREMELT = 2
DEFENSETYPE_PULSING = 3