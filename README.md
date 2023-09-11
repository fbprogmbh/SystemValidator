# SystemValidator
## Overview

**SystemValidator** is a powerful tool designed for checking configurations across various categories and generating an easily analyzable HTML report. It provides comprehensive assessment and validation in the following categories:

* **System Information**
* **PowerShell**
* **DSCLocalConfigurationManager**
* **User Right Assignments**
* **WinRM**
* **Network Configuration**
* **PSSession Configuration**
* **Windows Defender Configuration**

In addition to these categories, the SystemValidator also examines System Logs for the last 30 days, covering the following Event Logs:

* **PowerShell**
* **Windows Defender**
* **Windows Remote Management**
* **DSC**

## Installation

To start using the SystemValidator, follow these simple steps:

* **Download the ZIP file:** Begin by downloading the SystemValidator ZIP file from the repository. Alternatively head to the "Releases"-Tab and download the latest version from here: https://github.com/fbprogmbh/SystemValidator/releases
* **Run as Administrator:** Extract the contents of the ZIP file and locate the SystemValidator.ps1 script. Right-click on it and select "Run as Administrator."
* **Execution:** Allow the script to run, as it may take a few minutes to complete its assessments.
* **Output Report:** Once the script has finished, the final report will be generated and saved as an HTML file. You can find it at **C:\Temp\SystemValidatorOutput.html**.

Now you can analyze the report to gain insights into the configuration of your system in various critical areas.