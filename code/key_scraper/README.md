# On the Security of SSH Client Signatures - Artifacts

## SSH Public Key Scraper

This tool is designed to collect SSH public keys from Git-based platforms
such as GitHub, GitLab, and Launchpad. The tool supports both full and
incremental runs.

> [!WARNING]
> GitLab has recently implemented API restrictions to the Users API used
> by the GitLab scraping component. This will cause a significant reduction
> in collection speed. For more information, see [the announcement by GitLab](https://about.gitlab.com/blog/rate-limitations-announced-for-projects-groups-and-users-apis/).

## Building

Make sure Golang 1.23.0 or newer is available. To build the tool, simply run
`go build` inside this directory.

## Usage

Configuration is done via a `config.json` file. A file with reasonable
defaults is included as `config.sample.json`. Copy or rename this file to
`config.json`, insert your GitHub and GitLab API tokens, and then simply
run the tool without any CLI arguments. The default values for Elasticsearch
are inline with the Docker compose stack available in `../env_docker`.
