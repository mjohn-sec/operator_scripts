import xml.etree.ElementTree as ET

# Define high-value targets and corresponding ports/services
HIGH_VALUE_SERVICES = {
    "domain_controller": ["kerberos", "ldap", "microsoft-ds", "netlogon"],
    "dns_server": ["domain"],
    "mail_server": ["smtp", "pop3", "imap"],
    "file_server": ["smb", "microsoft-ds", "ftp", "nfs"],
    "database_server": ["mysql", "mssql", "postgresql", "oracle", "mongodb"],
    "web_server": ["http", "https", "http-alt"],
    "ssh_server": ["ssh"],
    "ntp_server": ["ntp"],
}

# Define ports for each high-value service if service names are not enough
SERVICE_PORTS = {
    "domain_controller": [88, 389, 636, 3268, 3269],
    "dns_server": [53],
    "mail_server": [25, 110, 143, 465, 587, 993, 995],
    "file_server": [139, 445, 21, 2049],
    "database_server": [3306, 1433, 5432, 1521, 27017],
    "web_server": [80, 443, 8080],
    "ssh_server": [22],
    "ntp_server": [123],
}

# Function to parse Nmap XML and identify high-value targets
def parse_nmap_xml(nmap_xml_file):
    tree = ET.parse(nmap_xml_file)
    root = tree.getroot()

    high_value_targets = {}

    # Iterate over each host in the XML file
    for host in root.findall("host"):
        ip_addr = host.find("address").get("addr")
        os_info = host.find("os")

        # Initialize dictionary for each host
        high_value_targets[ip_addr] = {
            "os": None,
            "services": []
        }
        
        # If OS info is available, extract OS name
        if os_info:
            os_name = os_info.find("osmatch").get("name")
            high_value_targets[ip_addr]["os"] = os_name

        # Iterate over all open ports on the host
        for port in host.findall("ports/port"):
            port_id = int(port.get("portid"))
            protocol = port.get("protocol")
            service = port.find("service")
            service_name = service.get("name") if service is not None else None

            # Check if this service or port matches high-value criteria
            for target_type, services in HIGH_VALUE_SERVICES.items():
                if service_name in services or port_id in SERVICE_PORTS[target_type]:
                    high_value_targets[ip_addr]["services"].append({
                        "target_type": target_type,
                        "port": port_id,
                        "protocol": protocol,
                        "service_name": service_name
                    })

    # Remove hosts with no high-value services
    high_value_targets = {ip: info for ip, info in high_value_targets.items() if info["services"]}
    return high_value_targets

# Function to display high-value targets in a readable format
def display_high_value_targets(high_value_targets):
    for ip, details in high_value_targets.items():
        print(f"IP Address: {ip}")
        if details["os"]:
            print(f"  OS: {details['os']}")
        for service in details["services"]:
            print(f"  Service: {service['service_name']} ({service['target_type']}) on port {service['port']}/{service['protocol']}")
        print()

# Main function to execute the script
if __name__ == "__main__":
    nmap_xml_file = "nmap_scan.xml"  # Replace with your Nmap XML output file
    high_value_targets = parse_nmap_xml(nmap_xml_file)
    if high_value_targets:
        print("High-Value Targets Identified:")
        display_high_value_targets(high_value_targets)
    else:
        print("No high-value targets found.")
