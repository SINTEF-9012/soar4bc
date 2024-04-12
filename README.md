# SOAR4BC: Digital Twin-based AI-driven Security Orchestration and Automatic Response with a dashboard based on NeoDash

## Installation

This software requires the following versions of node and yarn:

```
node version v20.2.0
yarn version v1.22.19
```

Install dependencies:

```
yarn install
```

Build local Docker image for MQtt-Kafka bridge (the rest of the Docker images are pulled from web):

```
docker build -t mqtt-kafka-bridge -f docker/Dockerfile .
```

Navigate to the `statistics` directory and build the Dockerfile for the statistics module:

```
docker build -t statistics -f Dockerfile .
```

Create an environment and install Python (v3.10), flask (v3.0.0), minio (v7.1.17), neo4j (v5.15.0), poetry (v1.7.1), openai (v0.28.1), pyyaml (v6.0.1), strenum (v0.4.15), dpkt (v1.9.8) and paho-mqtt (v1.6.1) OR use connection/environment.yml file to create Conda environment:
```
conda env create -f environment.yml
```
To verify installation: 
```
conda env list
```

## Setup

Launch databases in docker:

```
docker compose up
```

Run in another terminal:

```
yarn run dev
```

Activate the environment, navigate to the connection folder and run both `minio_api.py` and `neo4j_api.py` files by using the following commands: 
Activate the environment, navigate to the connection folder and run minio_api.py, neo4j_api.py and analytics_api.py files, using the following commands:

```
python minio_api.py
python neo4j_api.py
```

Navigate to the `statistics` directory, and run the following command (after having started the rest of the services as explained above):

```
docker run -p 5003:5003 --network=sindit_network -it statistics
```

### Populating Database and Dashboard


Open the minio database in browser: [http://localhost:9099](http://localhost:9099).
Log in with user name and password (detailed in docker compose file).

Create a user and set the policy to readwrite. The access and secret keys need to be updated in the `connection/minio_config.ini` file, and in `statistics/minio_config.ini`.
Create a bucket and update the bucket name in `connection/minio_api.py` file. Add the PCAP file to the bucket. 

Open the neo4j database in browser: [http://localhost:7474](http://localhost:7474).
Log in with user name and password (detailed in docker compose file).

Create a user and set the policy to readwrite. The access and secret keys need to be updated in the connection/minio_config.ini file.
Create a bucket and update the bucket name in connection/minio_api.py file. Add the file to the bucket. 

Open the dashboard in browser: [http://localhost:3000](http://localhost:3000), choose "New Dashboard". 
Log in with user name: neo4j, password: sindit-neo4j.

**Create database**: If the database is empty, you can load one by opening Neo4j Browser at [http://localhost:7474](http:localhost:7474). Copy the content in `samples/sample-data-updated.cypher` and paste it into the query box of the Neo4j browser, then execute the query. This query contains one example static data node and one analytics node. The name/type of the PCAP file needs to correspond to the endpoint/type properties of the static node and vice-versa. 

**Load dashboard**: To load a dashboard, press load dashboard button in left side panel. Choose "Select from file", and choose a sample database (e.g. dashboard-2023-12-05.json) in the "samples" folder in this repo. 

If the database is empty, you can load one by opening Neo4j Browser at http://localhost:7474 (log in using details in docker compose file). Copy the content in samples/sample-data-updated.cypher and paste it into the query box of the Neo4j browser, then execute the query. The name/type of the object file added in Minio needs to correspond to the endpoint/type properties of the static node. 

## Running SOAR Experiment based on MiniNet (Based on the work by Valtteri)

To initialize the database:

1. Find the data.cypher file from the `samples/data.cypher`.
2. Copy all the contents and paste them into the query box in Neo4j browser on at [http://localhost:7474](http:localhost:7474), then execute the query.


### NeoDash

After setting up Neo4j you can run the dashboard by opening the dashboard in browser: [http://localhost:3000](http://localhost:3000), choose "New Dashboard". 
Log in with user name: neo4j, password: sindit-neo4j.


To initialize the dashboard:

1. Find the dashboard.json file from the `samples/dashboard.json`.
2. Inside the dashboard, after you have created a New Dashboard and added the above shown credentials, click on the left panel on the page.
3. Click on the plus sign, and import dashboard.json.

## Configuring Test Bed

The test bed has 4 programs that run on it:

1. Mininet
2. Ryu SDN Controller
3. Shark (pyshark + Flask)
4. Open Policy Agent

### Initial Set-up:

To run and set-up Mininet, please read this guide:

https://mininet.org/download/

To ensure as little conflicts as possible, you should use option 1 from the guide with VirtualBox and the VM image provided, set up with a **Host-only Adapter on Adapter 2**. This should make it so that you are connecting to Mininet on eth1. Remember to allocate computing resources to the VM in the VirtualBox settings.

This test bed has been developed on Windows 11 with WSL and VirtualBox with Mininet VM.

On VirtualBox you can then start the Mininet VM. The username and password is:

```
username: mininet
password: mininet
```

Inside the mininet terminal, create and retrieve the IP address of the VM:

```
sudo dhclient eth1
ifconfig eth1
```

Copy the mn_code folder from local machine to the Mininet VM (copies to root, replace "mininet_ip" with the IP address from the VM.):

```
scp -r -P 22 mn_code mininet@<mininet_ip>:~/
```

Next up, create 4 local terminals. In all 4 of them, SSH into the Mininet VM:

```
ssh -Y -X mininet@<mininet_ip>
```

And you are all set up. You might have to update some programs.

### 1 Mininet

Mininet dependencies (if you get a X11 Error):

```
sudo xauth add `xauth list $DISPLAY`
```

To run Mininet:
mn_code is placed in inside `soar/mn_code`

```
cd mn_code
sudo mn --custom topology.py --topo topo --switch ovsk --controller remote -x
```

### 2 Ryu SDN Controller

Ryu dependencies:

```
pip install gunicorn==20.1.0 eventlet==0.30.2
```

```
pip install ryu
```

To run Ryu:

```
ryu-manager ryu.app.rest_firewall
```

### 3 Shark

Shark dependencies:

```
sudo dpkg-reconfigure wireshark-common
-> YES
```

```
sudo chmod +x /usr/bin/dumpcap
```

```
pip install pyshark
```

```
pip install flask
```

```
pip install requests
```

To run Shark:

```
cd mn_code
python shark.py
```

### 4 Open Policy Agent

Use the Docker image for running OPA:

```
docker run -p 8181:8181 openpolicyagent/opa \run --server --log-level debug
```

## SOAR

SOAR is run on the local machine.

Dependencies:

```
pip install requests
```

Inside the soar directory, run:

```
python soar.py <mininet_ip>
```

## Running Scenarios

From the pop-up terminals after running mininet, you can run data through the factory components to the gateway. Currently only the MQTT gateway is properly configured.

To run a gateway, find the **gw1_MQTT** terminal and run:

```
python gateway.py
```

To run data through a host, open one of the host terminals *(only DPS does something right now)* and run:

```
python host.py <data_file>
```

Press Ctrl+V to cancel the host program.

If you want to reset, you have to exit and then re-run:

1. Ryu
2. OPA
3. Shark
4. SOAR


### Running SOAR DDoS Experiment based on MiniNet 
All the files related to DDoS-Honeypot experiment are placed under DDoS_Honeypot Folder which is under the soar folder. 

# Prerequisite
Before running the experiment, make sure to install the Pentbox Honeypot Server and the required packages.  

# PentBox

-----------------
How to Install
-----------------

```
git clone https://github.com/technicaldada/pentbox
```

```
cd pentbox
```

```
tar -zxvf pentbox.tar.gz
```

```
cd pentbox
```

```
./pentbox.rb
```

Then select option number 2 and then option number 3. The Pentbox honeypot server should be up and running.



Next, install the required packages by running the following command:
```
pip3 install -r requirements.txt
```

## Manual
Create a virtual environment via Python: 
```
python3 -m venv venv
```

Activate the virtual environment:
```
source venv/bin/activate
```

Install all requirements as described in #Prerequisite.

Open separate terminals for each of the following steps:

1. Start the Ryu controller by running: 
```
ryu-manager customCtrl.py
```
2. Start the Toy Factory Digital Twin Network with honeypot server topology by running: 
```
python3 topology.py
```
3. Start the collecting and inspecting program by running: 
```
source collect.sh
```

4. Simulate Normal Traffic in Toy Factory Digital Twin Network by running (example below). We can vary for different hosts: 
```
h4_DPS source gentraffic.sh gw1_MQTT
```

5. Simulate DDoS Traffic in Toy Factory Digital Twin Network by running (example below). 
```
<IP_of_Host (h4_DPS)> hping3 --rand-source --flood <IP_of_Gateway (gw1_MQTT)>
```
```
hping3 -c 1000000 -i u1000 <IP_of_Target_Host/Gateway>
```


## Description
```.result```: Represents the classification result from the model, indicating whether the system is under a DDoS attack (true or false).\
```gentraffic.sh```: This script generates normal network traffic to simulate regular network operations within the Toy Factory Digital Twin. Ex: Run it as h4_DPS source gentraffic.sh gw1_MQTT\
```topology.py```: Toy Factory Digital Twin Network Topology with Honeypot Server. \
```realtime.csv```: This CSV file contains characteristic values extracted from network data, which are used for DDoS attack classification. \
```inspector```:  This script makes a call to the machine learning model for classifying given characteristic values as indicative of a DDoS attack or not. \
```customCtrl.py```: This Python script implements a custom Ryu controller to manage network operations, including handling flow rules and packet forwarding. \
```computeTuples.py```: This Python script computes 5 characteristic values from raw data collected from the network environment. \
```collect.sh```:  This shell script collects records from flow tables on OpenFlow switches, processes them, and extracts raw data for analysis. 

## Reference for DDoS Attack Simulation & Experiments
[1] [DDoSDN](https://github.com/icesonata/DDoSDN)

## User Guide for NeoDash

NeoDash comes with built-in examples of dashboards and reports. For more details on the types of reports and how to customize them, see the [User Guide](
https://neo4j.com/labs/neodash/2.2/user-guide/).

## Publish Dashboards

After building a dashboard, you can chose to deploy a read-only, standalone instance for users. See [Publishing](https://neo4j.com/labs/neodash/2.2/user-guide/publishing/) for more on publishing dashboards.


## Questions / Suggestions

If you have any questions about NeoDash, please reach out to the maintainers:
- Create an [Issue](https://github.com/neo4j-labs/neodash/issues/new) on GitHub for feature requests/bugs.
- Connect with us on the [Neo4j Discord](https://neo4j.com/developer/discord/).
- Create a post on the Neo4j [Community Forum](https://community.neo4j.com/).

> NeoDash is a free and open-source tool developed by the Neo4j community - not an official Neo4j product. If you have a need for a commercial agreement around training, custom extensions or other services, please contact the [Neo4j Professional Services](https://neo4j.com/professional-services/) team.
