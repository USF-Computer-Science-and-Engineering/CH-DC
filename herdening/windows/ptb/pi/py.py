import subprocess, requests
import io, zipfile
import json
import os
import xml.etree.ElementTree as ET
from rich.console import Console
from rich.table import Table
from rich.text import Text
import shutil


def main():
    choice = input("[0] Download and run tools, or [1] Parse local data? ")

    if choice == "0":
        get_pingcastle()
        get_sharphound()

        xml_file = find_first_xml()

        if xml_file:
            pingcastle_summary(xml_file)
            list_users_in_groups(xml_file)
        else:
            print("[ERROR] No PingCastle XML report found!")

        sharphound_summary("sharpout")

    elif choice == "1":
        xml = input("Location of PingCastle XML output (press Enter to auto-detect): ").strip()
        sharp = input("Location of SharpHound output directory: ").strip()

        if not xml:
            xml = find_first_xml()
            if not xml:
                print("[ERROR] No PingCastle XML report found!")
                return

        pingcastle_summary(xml)
        list_users_in_groups(xml)
        sharphound_summary(sharp)


def find_first_xml():
    """Find the first XML file in the current directory."""
    for file in os.listdir():
        if file.endswith(".xml"):
            return file
    return None


def get_pingcastle():
    repo_url = "https://github.com/netwrix/pingcastle/releases/latest"

    # Get the latest release page (GitHub redirects to the latest version tag)
    response = requests.get(repo_url, allow_redirects=True)
    if response.status_code != 200:
        print("Failed to access GitHub releases page.")
        return None

    # Extract the latest version from the redirected URL
    latest_version = response.url.rstrip('/').split("/")[-1]  # Extracts version like "3.0.1.0"
    print(f"Latest PingCastle Version: {latest_version}")

    # Construct the expected ZIP download URL
    download_url = f"https://github.com/netwrix/pingcastle/releases/download/{latest_version}/PingCastle_{latest_version}.zip"

    print(f"Downloading: {download_url}")
    
    # Download the ZIP file into memory
    response = requests.get(download_url, stream=True)
    
    if response.status_code == 200:
        zip_in_memory = io.BytesIO(response.content)  # Store ZIP in memory
        print(f"Download complete: {len(response.content)} bytes in memory.")
        
        # Open ZIP from memory and extract PingCastle.exe
        with zipfile.ZipFile(zip_in_memory, "r") as zip_ref:
            exe_name = None
            for filename in zip_ref.namelist():
                if filename.lower().endswith("pingcastle.exe"):
                    exe_name = filename
                    break
            
            if exe_name:
                print(f"Extracting {exe_name} to memory...")
                exe_data = zip_ref.read(exe_name)  # Read the .exe into memory
                
                # Write the .exe to a temporary location for execution
                exe_path = f"{exe_name}"
                with open(exe_path, "wb") as exe_file:
                    exe_file.write(exe_data)
                
                print(f"Executing {exe_path}...")
                subprocess.run([exe_path, "--healthcheck", "--level", "Full"], shell=True)  # Run PingCastle.exe
                
                return exe_path  # Return the executable path
            else:
                print("PingCastle.exe not found in the ZIP archive.")
                return None
    else:
        print("Failed to download the file. The URL might be incorrect.")
        return None



def get_sharphound():
    sharphound_url = "https://github.com/SpecterOps/SharpHound/releases/download/v2.5.13/SharpHound-v2.5.13.zip"
    console = Console()
    
    console.print(f"[bold blue]Downloading SharpHound from:[/bold blue] {sharphound_url}")
    response = requests.get(sharphound_url, stream=True)
    
    output_dir = "sharpout"
    if os.path.exists(output_dir):
        console.print(f"[bold yellow]Removing existing {output_dir} directory...[/bold yellow]")
        shutil.rmtree(output_dir)
    
    os.makedirs(output_dir, exist_ok=True)
    console.print(f"[bold green]{output_dir} directory has been reset.[/bold green]")


    if response.status_code == 200:
        zip_in_memory = io.BytesIO(response.content)
        console.print(f"[bold green]Download complete:[/bold green] {len(response.content)} bytes in memory.")
        
        # Extract ZIP contents
        with zipfile.ZipFile(zip_in_memory, "r") as zip_ref:
            exe_name = None
            for filename in zip_ref.namelist():
                if filename.lower().endswith("sharphound.exe"):
                    exe_name = filename
                    break
            
            if exe_name:
                console.print(f"[bold blue]Extracting {exe_name} to memory...[/bold blue]")
                exe_data = zip_ref.read(exe_name)
                exe_path = f"{exe_name}"
                
                # Write SharpHound.exe to a temporary file for execution
                with open(exe_path, "wb") as exe_file:
                    exe_file.write(exe_data)
                
                console.print(f"[bold yellow]Running SharpHound with max collection...[/bold yellow]")
                output_zip = "SharpHoundCollected.zip"
                subprocess.run([exe_path, "-c", "All", "--nozip", "--outputdirectory", "sharpout"], shell=True)
                
                # Extract results to "sharpout" folder
                output_dir = "sharpout"
                os.makedirs(output_dir, exist_ok=True)

                return exe_path  # Return the executable path
            else:
                console.print("[bold red]SharpHound.exe not found in the ZIP archive.[/bold red]")
                return None
    else:
        console.print("[bold red]Failed to download SharpHound. Check the URL.[/bold red]")
        return None



def pingcastle_summary(file_path):

    console = Console()
    
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        # Extract general domain information
        domain = root.find("./NetBIOSName").text if root.find("./NetBIOSName") is not None else "N/A"
        fqdn = root.find("./DomainFQDN").text if root.find("./DomainFQDN") is not None else "N/A"
        score = root.find("./GlobalScore").text if root.find("./GlobalScore") is not None else "N/A"
        date = root.find("./GenerationDate").text if root.find("./GenerationDate") is not None else "N/A"
        
        while True:
            console.print(Text("PingCastle Scan Summary", style="bold underline"))
            console.print(f"[bold]Domain:[/bold] {domain} ({fqdn})")
            console.print(f"[bold]Global Score:[/bold] {score}")
            console.print(f"[bold]Scan Date:[/bold] {date}\n")
            
            # Display summarized risk rules
            summary_table = Table(title="Risk Summary", show_header=True, header_style="bold red")
            summary_table.add_column("Index", justify="center", width=5)
            summary_table.add_column("Risk ID", style="dim", width=20)
            summary_table.add_column("Category", width=20)
            summary_table.add_column("Points", justify="right", width=10)
            
            risk_findings = []
            
            for index, risk in enumerate(root.findall("./RiskRules/HealthcheckRiskRule"), start=1):
                risk_id = risk.find("RiskId").text if risk.find("RiskId") is not None else "Unknown"
                category = risk.find("Category").text if risk.find("Category") is not None else "Unknown"
                points = risk.find("Points").text if risk.find("Points") is not None else "N/A"
                
                risk_findings.append((risk_id, category, points, risk))
                summary_table.add_row(str(index), risk_id, category, points)
            
            console.print(summary_table)
            
            # Ask user for detailed view
            console.print("[bold yellow]Enter the index of a risk to view details, or press Enter to exit:[/bold yellow]")
            user_input = input().strip()
            
            if user_input.isdigit():
                selected_index = int(user_input) - 1
                if 0 <= selected_index < len(risk_findings):
                    risk_id, category, points, risk = risk_findings[selected_index]
                    rationale = risk.find("Rationale").text if risk.find("Rationale") is not None else "No rationale"
                    details_list = [detail.text for detail in risk.findall("Details/string")]
                    detailed_info = "No details" if not details_list else ", ".join(details_list)
                    
                    console.print(Text("Detailed View of Selected Risk", style="bold underline"))
                    console.print(f"[bold]Risk ID:[/bold] {risk_id}")
                    console.print(f"[bold]Category:[/bold] {category}")
                    console.print(f"[bold]Points:[/bold] {points}")
                    console.print(f"[bold]Rationale:[/bold] {rationale}")
                    console.print(f"[bold]Details:[/bold] {detailed_info}")
                    
                    console.print("[bold yellow]Press Enter to go back to the main findings screen.[/bold yellow]")
                    input()
                else:
                    console.print("[bold red]Invalid selection. Please try again.[/bold red]")
            else:
                console.print("[bold green]Exiting without detailed view.[/bold green]")
                break
        
    except Exception as e:
        console.print(f"[bold red]Error parsing XML file:[/bold red] {e}")



def sharphound_summary(directory_path):
    console = Console()
    findings_summary = {
        "Kerberoastable Users": [],
        "Users with Preauth Not Required": [],
        "Users with Password Never Expires": [],
        "High Privilege Groups": [],
        "Unconstrained Delegation Accounts": [],
        "Users with Weak Encryption": [],
        "Users with AdminCount Set": [],
        "Computers with Unconstrained Delegation": [],
        "Users Trusted for Delegation": [],
        "Users with No Logon Restrictions": [],
        "Users with DCSync Rights": [],
        "Users with Shadow Credentials": [],
        "Abusable ACLs on Critical Objects": [],
        "Computers with Local Admins": [],
        "GPOs with Dangerous Permissions": [],
        "Users with Descriptions or Comments": []
    }
    
    try:
        for filename in os.listdir(directory_path):
            if filename.endswith(".json"):
                file_path = os.path.join(directory_path, filename)
                with open(file_path, "r") as f:
                    data = json.load(f)
                    for entry in data.get("data", []):
                        properties = entry.get("Properties", {})
                        
                        if properties.get("hasspn", False):
                            findings_summary["Kerberoastable Users"].append(properties.get("name", "Unknown"))
                        
                        if properties.get("dontreqpreauth", False):
                            findings_summary["Users with Preauth Not Required"].append(properties.get("name", "Unknown"))
                        
                        if properties.get("pwdneverexpires", False):
                            findings_summary["Users with Password Never Expires"].append(properties.get("name", "Unknown"))
                        
                        if properties.get("domain", "Unknown").lower().endswith(".local") and "admin" in properties.get("name", "").lower():
                            findings_summary["High Privilege Groups"].append(properties.get("name", "Unknown"))
                        
                        if properties.get("unconstraineddelegation", False):
                            findings_summary["Unconstrained Delegation Accounts"].append(properties.get("name", "Unknown"))
                        
                        if properties.get("supportedencryptiontypes") == 0:
                            findings_summary["Users with Weak Encryption"].append(properties.get("name", "Unknown"))
                        
                        if properties.get("admincount", False):
                            findings_summary["Users with AdminCount Set"].append(properties.get("name", "Unknown"))
                        
                        if properties.get("trustedtoauth", False):
                            findings_summary["Users Trusted for Delegation"].append(properties.get("name", "Unknown"))
                        
                        if properties.get("lastlogon", -1) == -1:
                            findings_summary["Users with No Logon Restrictions"].append(properties.get("name", "Unknown"))
                        
                        if "DCSync" in properties.get("name", ""):
                            findings_summary["Users with DCSync Rights"].append(properties.get("name", "Unknown"))
                        
                        if properties.get("shadowcredentials", False):
                            findings_summary["Users with Shadow Credentials"].append(properties.get("name", "Unknown"))
                        
                        if properties.get("abusableacls", False):
                            findings_summary["Abusable ACLs on Critical Objects"].append(properties.get("name", "Unknown"))
                        
                        if properties.get("localadmin", False):
                            findings_summary["Computers with Local Admins"].append(properties.get("name", "Unknown"))
                        
                        if properties.get("gpopermissions", False):
                            findings_summary["GPOs with Dangerous Permissions"].append(properties.get("name", "Unknown"))
                        
                        if properties.get("description") or properties.get("comment"):
                            user_info = f"{properties.get('name', 'Unknown')}: {properties.get('description', '')} {properties.get('comment', '')}"
                            findings_summary["Users with Descriptions or Comments"].append(user_info.strip())
        
        while True:
            console.print(Text("SharpHound Findings Summary", style="bold underline"))
            
            summary_table = Table(title="Findings Summary", show_header=True, header_style="bold blue")
            summary_table.add_column("Index", justify="center", width=5)
            summary_table.add_column("Finding Type", style="dim", width=40)
            summary_table.add_column("Count", justify="right", width=10)
            
            findings = list(findings_summary.items())
            for index, (finding_type, items) in enumerate(findings, start=1):
                summary_table.add_row(str(index), finding_type, str(len(items)))
            
            console.print(summary_table)
            
            console.print("[bold yellow]Enter the index of a finding to view details, or press Enter to exit:[/bold yellow]")
            user_input = input().strip()
            
            if user_input.isdigit():
                selected_index = int(user_input) - 1
                if 0 <= selected_index < len(findings):
                    finding_type, items = findings[selected_index]
                    console.print(Text(f"Detailed View of {finding_type}", style="bold underline"))
                    console.print("\n".join(items) if items else "No relevant data found.")
                    console.print("[bold yellow]Press Enter to go back to the main findings screen.[/bold yellow]")
                    input()
                else:
                    console.print("[bold red]Invalid selection. Please try again.[/bold red]")
            else:
                console.print("[bold green]Exiting without detailed view.[/bold green]")
                break
    
    except Exception as e:
        console.print(f"[bold red]Error parsing JSON files:[/bold red] {e}")

def list_users_in_groups(xml_file):
    console = Console()
    group_membership = {}

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        for group in root.findall("./PrivilegedGroups/HealthCheckGroupData"):
            group_name = group.find("GroupName").text if group.find("GroupName") is not None else "Unknown Group"
            members = [member.find("Name").text for member in group.findall("Members/HealthCheckGroupMemberData")] if group.findall("Members/HealthCheckGroupMemberData") else []
            group_membership[group_name] = members

        console.print(Text("Group Membership Summary from PingCastle", style="bold underline"))

        summary_table = Table(title="Groups and Their Members", show_header=True, header_style="bold cyan")
        summary_table.add_column("Group Name", style="dim", width=40)
        summary_table.add_column("Members", width=60)

        for group, members in group_membership.items():
            summary_table.add_row(group, ", ".join(members) if members else "No Members")

        console.print(summary_table)

    except Exception as e:
        console.print(f"[bold red]Error parsing PingCastle XML file:[/bold red] {e}")

main()



