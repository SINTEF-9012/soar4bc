from mininet.topo import Topo

# Mininet Topology Script
# Sets up a topology in Mininet

# Start up mininet:
# sudo mn --custom topology.py --topo topo --switch ovsk --controller remote -x

# Start up firewall:
# ryu-manager ryu.app.rest_firewall

# Copy code folder to mininet (copies to root):
# scp -r -P 22 mn_code mininet@<ip_address>:~/

class MyTopo(Topo):
    def __init__( self ):

        # Initialize topology
        Topo.__init__( self )

        # Host acting as reception/gateway
        host_MQTT_gateway = self.addHost('gw1_MQTT') # IP: 10.0.0.1
        host_OPCUA_gateway = self.addHost('gw2_OPCUA') # IP: 10.0.0.2

        # Add hosts
        host_HBW = self.addHost('h1_HBW') # IP: 10.0.0.3
        host_VGR = self.addHost('h2_VGR') # IP: 10.0.0.4
        host_SSC = self.addHost('h3_SSC') # IP: 10.0.0.5
        host_DPS = self.addHost('h4_DPS') # IP: 10.0.0.6
        host_MPO = self.addHost('h5_MPO') # IP: 10.0.0.7
        host_SLD = self.addHost('h6_SLD') # IP: 10.0.0.8

        # Add switches
        switch_mqtt = self.addSwitch('s1_mqtt') # DPID: 0000000000000001
        switch_opcua = self.addSwitch('s2_opcua') # DPID: 0000000000000002

        # Add links:
        # Links between switches and gateways
        self.addLink(host_MQTT_gateway, switch_mqtt)
        self.addLink(host_OPCUA_gateway, switch_opcua)

        # Links between factory component hosts and the MQTT switch (all 6 hosts)
        self.addLink(host_HBW, switch_mqtt)
        self.addLink(host_VGR, switch_mqtt)
        self.addLink(host_SSC, switch_mqtt)
        self.addLink(host_DPS, switch_mqtt)
        self.addLink(host_MPO, switch_mqtt)
        self.addLink(host_SLD, switch_mqtt)

        # Links between factory component hosts and the OPC-UA switch (3 hosts)
        self.addLink(host_HBW, switch_opcua)
        self.addLink(host_VGR, switch_opcua)
        self.addLink(host_SSC, switch_opcua)


topos = {'topo': ( lambda: MyTopo() )}