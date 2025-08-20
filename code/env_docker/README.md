# On the Security of SSH Client Signatures - Artifacts

## Docker Compose File for the Evaluation Environment

The Docker compose file contained in this directory is used to setup a
three-node Elasticsearch cluster that can be used by the SSH-Key-Scraper
tool (`../../tools/SSH-Key-Scraper`) as well as the evaluation scripts
in `../eval_scripts`.

### Requirements

To run this cluster, you will need a decently powered machine that can support
running three Elasticsearch nodes simultaneously. We recommend at least 64 GB of
RAM for all operations to run smoothly. You will also need a recent version of
Docker as the execution environment. Refer to the [Docker Docs](https://docs.docker.com/engine/install/)
for installation instructions.

Make sure to adjust the `MEM_LIMIT` environment variable in the .env file
to match your available resources. The environment variables specifies the
memory limit for each container in bytes.

### Running the Cluster

To run the cluster on your system, simply run `docker compose up -d` while
inside this directory. Similarly, running `docker compose down` will stop
the cluster. To remove all data of the cluster, run `docker compose down --volumes`,
which will remove the persistent volumes used by Docker.

### Accessing the Cluster

The compose stack will make one Elasticsearch host available on `localhost:9200`
by default. The default bind address and port on the host can be changed by
adjusting the `ES_PORT` variable in the `.env` file. Credentials for authentication
default to `elastic:elasticsearchpass` and can be changed through the
`ELASTIC_PASSWORD` environment variable in the `.env` file.

The stack also starts a Kibana container for easier inspection and visualization
of data through a web-based interface. By default, the Kibana host is available
at `localhost:5601`; authentication uses the `elastic` user mentioned previously.
Changing the bind address and port is possible by adjusting the `KIBANA_PORT`
environment variable in `.env`.
