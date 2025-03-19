#!/usr/bin/python
import os
from functools import partial

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch, OVSSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():

    OVSSwitch13 = partial(OVSSwitch, protocols='OpenFlow13')

    net = Mininet(topo=None, build=False, ipBase='10.0.0.0/8')

    info( '*** Adding remote Ryu controller\n' )
    c0 = net.addController(
        name='c0',
        controller=RemoteController,
        ip='127.0.0.1',
        protocol='tcp',
        port=6633
    )

    info( '*** Add switches\n')
    s1= net.addSwitch('s1_mqtt', cls=OVSKernelSwitch, dpid='0000000000000001')
    s2= net.addSwitch('s2_opcua', cls=OVSKernelSwitch, dpid='0000000000000002')

    info( '*** Add hosts\n')
    host_MQTT_gateway = net.addHost('gw1_MQTT', cls=Host, ip='10.0.0.1', defaultRoute=None)
    host_OPCUA_gateway = net.addHost('gw2_OPCUA', cls=Host, ip='10.0.0.2', defaultRoute=None)
    host_HBW = net.addHost('h1_HBW', cls=Host, ip='10.0.0.3', defaultRoute=None)
    host_VGR = net.addHost('h2_VGR', cls=Host, ip='10.0.0.4', defaultRoute=None)
    host_SSC = net.addHost('h3_SSC', cls=Host, ip='10.0.0.5', defaultRoute=None)
    host_DPS = net.addHost('h4_DPS', cls=Host, ip='10.0.0.6', defaultRoute=None)
    host_MPO = net.addHost('h5_MPO', cls=Host, ip='10.0.0.7', defaultRoute=None)
    host_SLD = net.addHost('h6_SLD', cls=Host, ip='10.0.0.8', defaultRoute=None)
    host_HPS = net.addHost('h7_HPS', cls=Host, ip='10.0.0.9', mac='00:00:00:00:00:09', defaultRoute=None)


    info( '*** Add links\n')
    net.addLink(host_MQTT_gateway, s1)
    net.addLink(host_OPCUA_gateway, s2)
    net.addLink(host_HBW, s1)
    net.addLink(host_VGR, s1)
    net.addLink(host_SSC, s1)
    net.addLink(host_DPS, s1)
    net.addLink(host_MPO, s1)
    net.addLink(host_SLD, s1)
    net.addLink(host_HPS, s1)
    net.addLink(host_HBW, s2)
    net.addLink(host_VGR, s2)
    net.addLink(host_SSC, s2)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s1_mqtt').start([c0])
    net.get('s2_opcua').start([c0])

    info( '*** Post configure switches and hosts\n')
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    myNetwork()
