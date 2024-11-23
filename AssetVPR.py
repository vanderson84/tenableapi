import requests

headers = {
    'X-ApiKeys': 'accessKey=YourAccesKey;secretKey=YorSecretKey',
    'Content-Type': 'application/json',
}

# Get a list of assets
response = requests.get('https://cloud.tenable.com/workbenches/assets', headers=headers)
assets = response.json()['assets']

# For each asset, obtain the vulnerabilities and calculate the average VPR
for asset in assets:
    hostname = asset.get('fqdn') or asset.get('netbios_name') or asset.get('ipv4') or "No Name"
    asset_id = asset['id']
    
    response = requests.get(f'https://cloud.tenable.com/workbenches/assets/{asset_id}/vulnerabilities', headers=headers)
    vulnerabilities = response.json()['vulnerabilities']
    
    # Filter vulnerabilities that have VPR
    vpr_vulnerabilities = [vuln for vuln in vulnerabilities if 'vpr_score' in vuln]
    
    if vpr_vulnerabilities:
        # Add only the VPRs of the vulnerabilities that have this field
        total_vpr = sum(float(vuln['vpr_score']) for vuln in vpr_vulnerabilities)
        # Calculate the average based only on vulnerabilities that have VPR
        average_vpr = total_vpr / len(vpr_vulnerabilities)
        print(f"Hostname: {hostname}, Average VPR: {average_vpr:.2f}")
    else:
        print(f"Hostname: {hostname} has no vulnerabilities with VPR.")
