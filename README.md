# Recon Tool

This is a simple recon tool that automates subdomain enumeration, scanning with Nuclei, port scanning with Nmap, and taking screenshots of web services with Gowitness, utilizing Axiom for dynamic infrastructure.

## Prerequisites

- Install [Golang](https://golang.org/dl/)
- Install [Axiom](https://github.com/pry0cc/axiom)
- Install [Subfinder](https://github.com/projectdiscovery/subfinder)
- Install [Nuclei](https://github.com/projectdiscovery/nuclei)
- Install [Nmap](https://nmap.org/download.html)
- Install [Gowitness](https://github.com/sensepost/gowitness)
- Install [jq](https://stedolan.github.io/jq/download/)

## Usage

1. Build the Go program:

```bash
go build recon.go
```

2. Run the tool:

```bash
./recon --domains domains.txt --config-subfinder subfinder_config.yaml --config-nuclei nuclei_config.yaml --output output_dir --fleet fleet_name
```

- `--domains`: Path to a txt file containing the list of domains and hosts.
- `--config-subfinder`: (Optional) Path to a custom Subfinder config file.
- `--config-nuclei`: (Optional) Path to a custom Nuclei config file.
- `--output`: (Optional) Path to the output directory. Defaults to "output".
- `--fleet`: (Optional) Name of the Axiom fleet. Defaults to "recon-fleet".

## Output

The tool will create an output directory containing the following CSV files:

- `subdomains.csv`: Subdomains discovered by Subfinder.
- `nuclei_output.csv`: Results of the Nuclei scan.
- `nmap_output.csv`: Results of the Nmap port scan.
- `gowitness_output.csv`: Screenshot and metadata results from Gowitness.

## Notes

The tool will spin up an Axiom fleet and copy the specified config files to the instances before the scan runs. The config files should be formatted according to the requirements of each tool (Subfinder, Nuclei).
