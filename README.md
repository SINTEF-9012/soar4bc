# MADT4BC: Multi-Aspect Digital Twin for Business Continuity

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

Build local Docker image (the rest of the Docker images are pulled from web):

```
docker build -t mqtt-kafka-bridge -f docker/Dockerfile .
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

Activate the environment, navigate to the connection folder and run minio_api.py, neo4j_api.py and analytics_api.py files, using the following command:

    python (filename).py

### Populating Database and Dashboard

Open the minio database in browser: http://localhost:9099.
Log in with user name and password (detailed in docker compose file).
Create a user and set the policy to readwrite. The access and secret keys need to be updated in the connection/minio_config.ini file.
Create a bucket and update the bucket name in connection/minio_api.py file. Add the file to the bucket. 

Open the dashboard in browser: http://localhost:3000, choose "New Dashboard". 
Log in with user name: neo4j, password: sindit-neo4j.

To load a dashboard, press load dashboard button in left side panel. Choose "Select from file", and choose a dashboard (e.g. dashboard-2023-12-05.json) from the "samples" folder. 

If the database is empty, you can load one by opening Neo4j Browser at http://localhost:7474 (log in using details in docker compose file). Copy the content in samples/sample-data-updated.cypher and paste it into the query box of the Neo4j browser, then execute the query. The name/type of the object file added in Minio needs to correspond to the endpoint/type properties of the static node. 


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
