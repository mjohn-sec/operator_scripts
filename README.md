

Nmap High Value Targets 

This script uses the xml.etree.ElementTree module to parse the Nmap output and searches for specific services commonly associated with high-value targets such as domain controllers, DNS servers, mail servers, file servers, and database servers on both Windows and Linux environments.

To run this script, you must:

- Run an Nmap scan and export the output as an XML file (using the -oX option).
- Use this script to parse that XML and identify high-value targets based on service types and specific open ports.

Explanation
Definitions of High-Value Targets: The script defines common service names and ports associated with each high-value target category. These include:

- Domain Controllers: Kerberos, LDAP, etc.
-DNS Servers: DNS protocol (port 53).
-Mail Servers: SMTP, POP3, IMAP.
-File Servers: SMB, FTP, NFS.
-Database Servers: MySQL, MSSQL, PostgreSQL, Oracle, MongoDB.
-Web Servers: HTTP, HTTPS.

XML Parsing with xml.etree.ElementTree: The parse_nmap_xml() function
parses the Nmap XML file, iterating over each host and checking for open ports and service names. It then checks if each service or port matches any of the high-value categories.

Result Display: The display_high_value_targets() function formats the output, printing each high-value service found on the target hosts along with details.

How to Run
- Save the script as high_value_target_finder.py.
- Run your Nmap scan with XML output:

nmap -oX nmap_scan.xml [target]

- Run the script:

python high_value_target_finder.py

This script provides an automated way to sift through Nmap results and highlight potential high-value targets that could prioritize attack vectors.
