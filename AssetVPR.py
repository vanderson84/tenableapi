import requests

headers = {
    'X-ApiKeys': 'accessKey=41583d7b0aeef7330350e08fc243bff7a1f52ea0d0a5a1361c756b826c36c3ed;secretKey=8e945a12dffd34b20ce0d38f6c8f2cf193c03e75fa54acd9861ab80a467ab7b2',
    'Content-Type': 'application/json',
}

# Obtenha a lista de ativos
response = requests.get('https://cloud.tenable.com/workbenches/assets', headers=headers)
assets = response.json()['assets']

# Para cada ativo, obtenha as vulnerabilidades e calcule a média do VPR
for asset in assets:
    hostname = asset.get('fqdn') or asset.get('netbios_name') or asset.get('ipv4') or "Sem Nome"
    asset_id = asset['id']
    
    response = requests.get(f'https://cloud.tenable.com/workbenches/assets/{asset_id}/vulnerabilities', headers=headers)
    vulnerabilities = response.json()['vulnerabilities']
    
    # Filtrar vulnerabilidades que possuem VPR
    vpr_vulnerabilities = [vuln for vuln in vulnerabilities if 'vpr_score' in vuln]
    
    if vpr_vulnerabilities:
        # Somar apenas os VPRs das vulnerabilidades que possuem esse campo
        total_vpr = sum(float(vuln['vpr_score']) for vuln in vpr_vulnerabilities)
        # Calcular a média com base apenas nas vulnerabilidades que possuem VPR
        average_vpr = total_vpr / len(vpr_vulnerabilities)
        print(f"Hostname: {hostname}, Média VPR: {average_vpr:.2f}")
    else:
        print(f"Hostname: {hostname} não possui vulnerabilidades com VPR.")