\# ScheduledTask\_Abuse



PowerShell proof-of-concept scripts for studying Windows Scheduled Task behavior in a controlled Active Directory environment.



The project focuses on executing operations in the context of an already interactive user session and demonstrating the associated security impact in an authorized lab environment.



\## Scripts



\### ScheduledTask\_Exec.ps1



Minimal proof of concept demonstrating command execution through a Windows Scheduled Task in the context of a target interactive user.



This script can be used to validate the Scheduled Task execution mechanism before testing more complex operations.



\### ScheduledTask\_CertReq.ps1



Proof of concept demonstrating certificate enrollment through a Windows Scheduled Task running in the context of a target interactive user.



The script performs the following high-level operations:



1\. Prepares a working directory.

2\. Generates a certificate request configuration.

3\. Creates a Scheduled Task associated with the target interactive user.

4\. Performs certificate enrollment against the specified Certification Authority.

5\. Exports the resulting certificate as a PFX file.

6\. Removes the temporary Scheduled Task.



\## Lab



The scripts were designed for Active Directory / AD CS research environments.



Example lab components:



\- Active Directory Domain Services

\- Active Directory Certificate Services

\- Windows workstation

\- Interactive domain user session

\- Windows Task Scheduler



\## Requirements



\- Windows PowerShell

\- Windows Task Scheduler

\- Active Directory environment

\- AD CS Certification Authority for certificate enrollment testing

\- Appropriate permissions for Scheduled Task creation



\## Security Notice



These scripts are provided for educational purposes, security research, and authorized penetration testing only.



Use them exclusively on systems that you own or for which you have explicit authorization to perform security testing.



The author is not responsible for unauthorized or malicious use of this project.



\## Author



Chems-Eddine TIMAKSSAT

