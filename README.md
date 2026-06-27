# VulnDriverFinder

VulnDriverFinder is a tool that scrapes browses catalog.microsoft for vuln drivers for potentially vulnerable drivers based on imported functions

## How the detection of potentially vulnerable drivers works

- The tool downloads the zipped driver package from the microsoft catalog and checks the imports for functions that allow to map physical memory
- It then also checks if the driver imports for IofCompleteRequest which is used to handle IOCTL commands

This means each driver flagged by the tool most likely uses IOCTL to communicate with a usermode controller and uses functions that can map physical memory, these drivers can be reversed to see if usermode information is used as a parameter to any of the critical functions.

## How to use Claude Code to auto create a PoC and detailed analysis of the driver:
### Claude Code
You need to download the claude code CLI and authenticate yourself so you can run the command claude
### IDA Integration
You need to follow the steps in this github documentation: https://github.com/mrexodia/ida-pro-mcp to enable claude to use IDA via MCP

## Examples
An example of a vulnerable driver with a detailed analysis and PoC fully written by claude can be found in the RE folder
