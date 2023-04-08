package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	var domainsFile, subfinderConfig, nucleiConfig, outputDirectory, fleetName string
	flag.StringVar(&domainsFile, "domains", "", "Path to a txt file containing the list of domains and hosts.")
	flag.StringVar(&subfinderConfig, "config-subfinder", "", "Path to a custom Subfinder config file.")
	flag.StringVar(&nucleiConfig, "config-nuclei", "", "Path to a custom Nuclei config file.")
	flag.StringVar(&outputDirectory, "output", "output", "Path to the output directory.")
	flag.StringVar(&fleetName, "fleet", "recon-fleet", "Name of the Axiom fleet.")
	flag.Parse()

	if domainsFile == "" {
		log.Fatal("Please provide a domains file with the --domains flag.")
	}

	domainsData, err := ioutil.ReadFile(domainsFile)
	if err != nil {
		log.Fatalf("Error reading domains file: %v", err)
	}
	domains := strings.Split(strings.TrimSpace(string(domainsData)), "\n")

	for _, domain := range domains {
		reconDomain(domain, subfinderConfig, nucleiConfig, outputDirectory, fleetName)
	}
}

func reconDomain(target, subfinderConfig, nucleiConfig, outputBase, fleetName string) {
	subdomainsFile := filepath.Join(outputBase, "subdomains.csv")
	nucleiOutput := filepath.Join(outputBase, "nuclei_output.csv")
	nmapOutput := filepath.Join(outputBase, "nmap_output.csv")
	gowitnessOutput := filepath.Join(outputBase, "gowitness_output.csv")

	if err := os.MkdirAll(outputBase, os.ModePerm); err != nil {
		log.Fatalf("Error creating output directory: %v", err)
	}

	// Spin up the fleet
	axiomExec("fleet", fleetName)

	// Copy config files to Axiom instances
	if subfinderConfig != "" {
		subfinderConfigName := filepath.Base(subfinderConfig)
		axiomSCP(subfinderConfig, fleetName+":~/"+subfinderConfigName)
		subfinderConfig = "--config-file=" + subfinderConfigName
	}

	if nucleiConfig != "" {
		nucleiConfigName := filepath.Base(nucleiConfig)
		axiomSCP(nucleiConfig, fleetName+":~/"+nucleiConfigName)
		nucleiConfig = "--config=" + nucleiConfigName
	}

	// Step 1: Subdomain enumeration using Subfinder with Axiom
	fmt.Println("Starting subdomain enumeration with Subfinder using Axiom...")
	subfinderOut := filepath.Join(outputBase, "subfinder_raw.json")
	axiomScan(target, "subfinder", subfinderOut, fleetName, subfinderConfig)
	saveCSV(subfinderOut, subdomainsFile, ".[] | [.name]")

	// Step 2: Running Nuclei templates on discovered subdomains with Axiom
	fmt.Println("Running Nuclei on discovered subdomains using Axiom...")
	nucleiOut := filepath.Join(outputBase, "nuclei_raw.json")
	axiomScan(subdomainsFile, "nuclei", nucleiOut, fleetName, nucleiConfig, "-p", "/path/to/nuclei-templates/")
	saveCSV(nucleiOut, nucleiOutput, ".[] | [.host, .templateID, .info.name, .info.severity]")

	// Step 3: Port scanning using Nmap with Axiom
	fmt.Println("Starting port scanning with Nmap using Axiom...")
	nmapOut := filepath.Join(outputBase, "nmap_raw.json")
	axiomScan(subdomainsFile, "nmap", nmapOut, fleetName, "-p-", "-T2", "-sV", "--script=http-title")
	saveCSV(nmapOut, nmapOutput, ".[] | [.host, .ports[].port, .ports[].service.name, .ports[].service.version, .ports[].service.extrainfo, .ports[].scriptResults[].output]")

	// Step 4: Screenshotting web services with Gowitness using Axiom
	fmt.Println("Starting screenshotting web services with Gowitness using Axiom...")
	gowitnessOut := filepath.Join(outputBase, "gowitness_raw.json")
	axiomScan(subdomainsFile, "gowitness", gowitnessOut, fleetName, "screenshot", "--disable-geolocation")
	saveCSV(gowitnessOut, gowitnessOutput, ".[] | [.url, .responseCode, .title, .headers.Server, .headers.XPoweredBy]")
}

func axiomExec(args ...string) {
	cmd := exec.Command("axiom", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("Error running axiom command: %v", err)
	}
}

func axiomSCP(src, dest string) {
	cmd := exec.Command("axiom-scp", src, dest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("Error running axiom-scp command: %v", err)
	}
}

func axiomScan(target, module, outFile, fleetName string, args ...string) {
	cmdArgs := []string{"scan", target, "-m", module, "-oA", outFile, "-f", fleetName}
	cmdArgs = append(cmdArgs, args...)
	axiomExec(cmdArgs...)
}

func saveCSV(jsonFile, csvFile, jqFilter string) {
	jsonData, err := ioutil.ReadFile(jsonFile)
	if err != nil {
		log.Fatalf("Error reading JSON file: %v", err)
	}

	jqCmd := exec.Command("jq", "-r", jqFilter)
	jqCmd.Stdin = strings.NewReader(string(jsonData))

	csvData, err := jqCmd.Output()
	if err != nil {
		log.Fatalf("Error running jq command: %v", err)
	}

	if err := ioutil.WriteFile(csvFile, csvData, 0644); err != nil {
		log.Fatalf("Error writing CSV file: %v", err)
	}
}
