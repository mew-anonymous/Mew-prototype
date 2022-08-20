# Mew-prototype
Link-flooding attacks (LFAs) can cut off internet to selected server targets, and are hard to mitigate because adversaries use normal-looking and low-rate flows and can dynamically adjusts the attack strategy. Traditional centralized defense systems cannot locally and efficiently suppress malicious traffic. Though emerging programmable switches offer an opportunity to bring defense systems closer to targeted links, their limited resource and lack of support for runtime reconfiguration limit their usage for link-flooding defenses. 

We have proposed Mew, a resource-efficient and runtime adaptable link-flooding defense system. Mew can counter various LFAs even when a massive number of flows are concentrated on a link, or when the attack strategy changes quickly. We design a distributed storage mechanism and a lossless state migration mechanism to reduce a storage bottleneck of programmable networks. We develop cooperative defense APIs to support multi-grained co-detection and co-mitigation without excessive overhead. Mew's dynamic defense mechanism can constantly analyze network conditions and activate corresponding defenses without rebooting devices or interrupting other running functions. 

# Experiment setup
- Switch: H3C S9830 with tofino chip (other programmable switches such Wedge 100BF-32X should be OK)
- Barefoot SDE: bf-sde-9.1.0
- Server: H3C 3030g
# Description
An edge switch is the switch directly connecting to outside networks (hosts). 

A core switch is the switch only connecting to other switches and inside hosts.

The following shows the example for the simplest topology (only a edge and a core switch). If you want to use other topology, mofidy the routing file in ```./$DEFENSE_TYPE$/initial_script/*_local.py``` (install the initial routing rules) or add routing rules manually.

Example topology:  ```Host -- (port 0) Edge (port 1) -- (port 1) Core (port 0) -- Inside Host ```

# Run the code
**Step 0:** Please ensure you have install the barefoot SDE. Use at least two switches and connect them.

Set environment variable ```SDE=~/bf-sde-9.1.0/```
Download the source code: 
```
cd $SDE/
git clone https://github.com/mew-anonymous/Mew-prototype
```

**Step 1:** In the edge switch, build and run the P4 program ```$DEFENSE_TYPE$/$DEFENSE_P4PROGRAM$``` (e.g., ```crossfire/mew-edge-crossfire.p4```, then $DEFENSE_TYPE$=crossfire, $DEFENSE_P4PROGRAM$=mew-edge-crossfire.p4):

Open a new terminal
```
cd $SDE/pkgsrc/p4-build
./configure --prefix=$SDE_INSTALL --with-tofino --with-p4c=p4c --bindir=$SDE_INSTALL/bin P4_NAME=mew_edge_$DEFENSE_TYPE$ P4_PATH=$SDE/Mew-prototype/edge/$DEFENSE_TYPE$/$DEFENSE_P4PROGRAM$ P4_VERSION=p4-16 P4_ARCHITECTURE=tna --enable-thriftcd  && make && make install
cd $SDE/
./run_switchd.sh -p mew_edge_$DEFENSE_TYPE$
```

Open a new terminal
```
cd $SDE/
./run_p4_tests.sh -p mew_edge_$DEFENSE_TYPE$ -t ./Mew-prototype/edge/$DEFENSE_TYPE$/initial_script/
```
**Step 2:** In the core switch, build and run the P4 program ```$DEFENSE_TYPE$/$DEFENSE_P4PROGRAM$``` (e.g., ```crossfire/mew-core-crossfire.p4```, then $DEFENSE_TYPE$=crossfire, $DEFENSE_P4PROGRAM$=mew-core-crossfire.p4):

Open a new terminal
```
cd $SDE/pkgsrc/p4-build
./configure --prefix=$SDE_INSTALL --with-tofino --with-p4c=p4c --bindir=$SDE_INSTALL/bin P4_NAME=mew_core_$DEFENSE_TYPE$ P4_PATH=$SDE/Mew-prototype/core/$DEFENSE_TYPE$/$DEFENSE_P4PROGRAM$ P4_VERSION=p4-16 P4_ARCHITECTURE=tna --enable-thriftcd  && make && make install
cd $SDE/
./run_switchd.sh -p mew_core_$DEFENSE_TYPE$
```

Open a new terminal
```
cd $SDE/
./run_p4_tests.sh -p mew_core_$DEFENSE_TYPE$ -t ./Mew-prototype/core/$DEFENSE_TYPE$/initial_script/
./run_p4_tests.sh -p mew_core_$DEFENSE_TYPE$ -t ./Mew-prototype/core/$DEFENSE_TYPE$/reactor_script/
```
