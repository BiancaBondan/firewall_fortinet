import pandas as pd
from netmiko import ConnectHandler
import traceback
import re 
import os


################################################################# LER DADOS ###############################################################################

def verificar_formato_excel(caminho_excel):
    df = pd.read_excel(caminho_excel)
    colunas = df.columns
    if len(colunas) < 4:
        print("O arquivo Excel deve ter pelo menos três colunas: ORIGEM, DESTINO, PORTAS e FIREWALL. IPS E PORTAS separadas por vírgulas")
        return False
    if colunas[0].lower() != 'origem' or colunas[1].lower() != 'destino' or colunas[2].lower() != 'portas' or colunas[3].lower() != 'firewall':
        print("As primeiras três colunas do arquivo Excel devem ser: ORIGEM, DESTINO, PORTAS e FIREWALL.")
        return False
    return True


#################################################################### FIREWALL ###############################################################################
def ler_firewall(fw):
    fw_list = [ip_fw.strip() for ip_fw in fw.split(',')]
    return fw_list

def conectar_fW(ip_fw):
    conectar_fW = {
        'device_type': 'fortinet',
        'ip': ip_fw,
        'username': '',  
        'password': '', 
        'port': 22,
    }
    net_connect = ConnectHandler(**conectar_fW)
    print(f"Acesso ao firewall {ip_fw}")
    return net_connect

######################################################### IP ORIGEM ##########################################################

def calcular_mascara_o(prefixo_o):
    mascaras_o = {
        0: "0.0.0.0",
        1: "128.0.0.0",
        2: "192.0.0.0",
        3: "224.0.0.0",
        4: "240.0.0.0",
        5: "248.0.0.0",
        6: "252.0.0.0",
        7: "254.0.0.0",
        8: "255.0.0.0",
        9: "255.128.0.0",
        10: "255.192.0.0",
        11: "255.224.0.0",
        12: "255.240.0.0",
        13: "255.248.0.0",
        14: "255.252.0.0",
        15: "255.254.0.0",
        16: "255.255.0.0",
        17: "255.255.128.0",
        18: "255.255.192.0",
        19: "255.255.224.0",
        20: "255.255.240.0",
        21: "255.255.248.0",
        22: "255.255.252.0",
        23: "255.255.254.0",
        24: "255.255.255.0",
        25: "255.255.255.128",
        26: "255.255.255.192",
        27: "255.255.255.224",
        28: "255.255.255.240",
        29: "255.255.255.248",
        30: "255.255.255.252",
        31: "255.255.255.254",
        32: "255.255.255.255",
    }
    return mascaras_o.get(prefixo_o)


def process_origem(origem):
    origem_list = []
    for item in origem.split(','):
        try:
            ip_origem, prefixo_o = (item.split('/') + ['32'])[:2]
            prefixo_o = int(prefixo_o)
            mascara_o = calcular_mascara_o(prefixo_o)
            origem_list.append({
                'ip_origem': ip_origem,
                'prefixo_o': prefixo_o,
                'mascara_o': mascara_o
            })
            print("Origem list preenchida")
        except Exception as e:
            print(f"Erro ao processar a origem {item}: {str(e)}")
    return origem_list



porta_origem = 0



def check_routing_o(net_connect, ip_origem):
    output_routing_o = net_connect.send_command(f"get router info routing-table details {ip_origem}")
    interfaces_o = []

    if not output_routing_o:
        return []

    for line in output_routing_o.splitlines():
        line = line.strip()

        if line.startswith("*"):
            parts = line.split(",")
            if len(parts) > 1:
                after_comma = parts[1].strip()
                if "via" in after_comma:
                    interface_name_o = after_comma.split("via")[1].strip()
                else:
                    interface_name_o = after_comma

                if interface_name_o:
                    interfaces_o.append(interface_name_o)

    zones_o = []

    for interface_name_o in interfaces_o:
        output_zones_o = net_connect.send_command(f"show system zone | grep -f {interface_name_o}")
        zone_found = False

        for line in output_zones_o.splitlines():
            line = line.strip()

            if line.startswith("edit"):
                current_zone_o = line.split('"')[1]
                zones_o.append({
                    'zone_name_o': current_zone_o,
                    'interface_name_o': interface_name_o,
                })
                zone_found = True
                break  


        if not zone_found:
                    output_sdwan_o = net_connect.send_command("show system sdwan")
                    current_interface = None
                    for line in output_sdwan_o.splitlines():
                        line = line.strip()

                        if line.startswith("config members"):
                            current_interface = None  

                        elif line.startswith("set interface") and '"' in line:
                            current_interface = line.split('"')[1]

                        elif current_interface == interface_name_o and line.startswith("set zone") and '"' in line:
                            sdwan_zone_o = line.split('"')[1]
                            zones_o.append({
                                'zone_name_o': sdwan_zone_o,
                                'interface_name_o': interface_name_o
                            })
                            zone_found = True
                            break

        if not zone_found:
            zones_o.append({
                'zone_name_o': '', 
                'interface_name_o': interface_name_o
            })



def add_zones_to_o(net_connect, origem_list):
    for origem in origem_list:
        ip_origem = origem.get('ip_origem')
        zones_o = check_routing_o(net_connect, ip_origem)

        if zones_o:
            origem['zone_name_o'] = [zone['zone_name_o'] for zone in zones_o if zone['zone_name_o']]
            origem['interface_name_o'] = [zone['interface_name_o'] for zone in zones_o]
    return origem_list



def check_address_o(net_connect, origem_list):
    add_exists_o = []
    add_create_o = []

    for origem in origem_list:
        ip_origem = origem.get('ip_origem')
        prefixo_o = origem.get('prefixo_o')
        mascara_o = origem.get('mascara_o')
        zones_o = {
            'zone_name_o': origem.get('zone_name_o', 'Zona_Indefinida'),
            'interface_name_o': origem.get('interface_name_o', 'Interface_Indefinida')
        }
        command = f"show firewall address | grep -f {ip_origem}"
        output_fw_add_o = net_connect.send_command(command)

        edit_line = None
        objeto_nome_o = None

        for line in output_fw_add_o.splitlines():
            if "edit" in line:
                edit_line = line.strip()
                objeto_nome_o = edit_line.split()[1].strip('"') 

            if "set subnet" in line:
                parts = line.split()
                
                if len(parts) >= 4 and parts[2] == ip_origem and parts[3] == mascara_o:
                    if objeto_nome_o: 
                        add_exists_o.append({
                            'ip_origem': ip_origem,
                            'prefixo_o': prefixo_o,
                            'mascara_o': mascara_o,
                            'objeto_nome_o': objeto_nome_o,
                            'zona_ou_interface': zones_o.get('zone_name_o', zones_o.get('interface_name_o'))
                        })
                        break  

        if not any(o['ip_origem'] == ip_origem for o in add_exists_o):
            objeto_nome_o = f"H_{ip_origem}/{prefixo_o}" if prefixo_o == "32" else f"N_{ip_origem}/{prefixo_o}"
            nova_entrada = {
                'ip_origem': ip_origem,
                'prefixo_o': prefixo_o,
                'mascara_o': mascara_o,
                'objeto_nome_o': objeto_nome_o,
                'zona_ou_interface': zones_o.get('zone_name_o', zones_o.get('interface_name_o'))
            }
            add_create_o.append(nova_entrada)

    return add_exists_o, add_create_o



############################## IP  DESTINO ####################################

def calcular_mascara_d(prefixo_d):
    mascaras_d = {
        0: "0.0.0.0",
        1: "128.0.0.0",
        2: "192.0.0.0",
        3: "224.0.0.0",
        4: "240.0.0.0",
        5: "248.0.0.0",
        6: "252.0.0.0",
        7: "254.0.0.0",
        8: "255.0.0.0",
        9: "255.128.0.0",
        10: "255.192.0.0",
        11: "255.224.0.0",
        12: "255.240.0.0",
        13: "255.248.0.0",
        14: "255.252.0.0",
        15: "255.254.0.0",
        16: "255.255.0.0",
        17: "255.255.128.0",
        18: "255.255.192.0",
        19: "255.255.224.0",
        20: "255.255.240.0",
        21: "255.255.248.0",
        22: "255.255.252.0",
        23: "255.255.254.0",
        24: "255.255.255.0",
        25: "255.255.255.128",
        26: "255.255.255.192",
        27: "255.255.255.224",
        28: "255.255.255.240",
        29: "255.255.255.248",
        30: "255.255.255.252",
        31: "255.255.255.254",
        32: "255.255.255.255",
    }
    return mascaras_d.get(prefixo_d)


def process_destino(destino):
    destino_list = []
    for item in destino.split(','):
        try:
            ip_destino, prefixo_d = (item.split('/') + ['32'])[:2]
            prefixo_d = int(prefixo_d)
            mascara_d = calcular_mascara_d(prefixo_d)
            destino_list.append({
                'ip_destino': ip_destino,
                'prefixo_d': prefixo_d,
                'mascara_d': mascara_d
            })
            print("Destino list preenchida")

        except Exception as e:
            print(f"Erro ao processar o destino {item}: {str(e)}")

    return destino_list



def check_routing_d(net_connect, ip_destino):
    output_routing_d = net_connect.send_command(f"get router info routing-table details {ip_destino}")
    interfaces_d = []

    if not output_routing_d:
        return []

    for line in output_routing_d.splitlines():
        line = line.strip()

        if line.startswith("*"):
            parts = line.split(",")
            if len(parts) > 1:
                after_comma = parts[1].strip()
                if "via" in after_comma:
                    interface_name_d = after_comma.split("via")[1].strip()
                else:
                    interface_name_d = after_comma

                if interface_name_d:
                    interfaces_d.append(interface_name_d)

    zones_d = []

    for interface_name_d in interfaces_d:
        output_zones_d = net_connect.send_command(f"show system zone | grep -f {interface_name_d}")
        zone_found = False
        for line in output_zones_d.splitlines():
            line = line.strip()

            if line.startswith("edit"):
                current_zone_d = line.split('"')[1]
                zones_d.append({
                    'zone_name_d': current_zone_d,
                    'interface_name_d': interface_name_d,
                })
                zone_found = True
                break


        if not zone_found:
            output_sdwan_d = net_connect.send_command("show system sdwan")
            current_interface = None
            for line in output_sdwan_d.splitlines():
                line = line.strip()

                if line.startswith("config members"):
                    current_interface = None  

                elif line.startswith("set interface") and '"' in line:
                    current_interface = line.split('"')[1]

                elif current_interface == interface_name_d and line.startswith("set zone") and '"' in line:
                    sdwan_zone_d = line.split('"')[1]
                    zones_d.append({
                        'zone_name_d': sdwan_zone_d,
                        'interface_name_d': interface_name_d
                    })
                    zone_found = True
                    break

        if not zone_found:
            zones_d.append({
                'zone_name_d': '', 
                'interface_name_d': interface_name_d
            })

    return zones_d

                 

def add_zones_to_d(net_connect, destino_list):
    for destino in destino_list:
        ip_destino = destino.get('ip_destino')
        zones_d = check_routing_d(net_connect, ip_destino)

        if zones_d:
            destino['zones_d'] = zones_d
            destino['zone_names_d'] = [zone['zone_name_d'] for zone in zones_d if zone['zone_name_d']]
            destino['interfaces_d'] = [zone['interface_name_d'] for zone in zones_d]

    return destino_list


def check_address_d(net_connect, destino_list):
    add_exists_d = []
    add_create_d = []

    for destino in destino_list:
        ip_destino = destino.get('ip_destino')
        prefixo_d = destino.get('prefixo_d')
        mascara_d = destino.get('mascara_d')
        zones_d = {
            'zone_name_d': destino.get('zone_name_d', 'Zona_Indefinida'),
            'interface_name_d': destino.get('interface_name_d', 'Interface_Indefinida')
        }

        command = f"show firewall address | grep -f {ip_destino}"
        output_fw_add_d = net_connect.send_command(command)

        edit_line = None
        objeto_nome_d = None

        for line in output_fw_add_d.splitlines():
            if "edit" in line:
                edit_line = line.strip()
                objeto_nome_d = edit_line.split()[1].strip('"')  

            if "set subnet" in line:
                parts = line.split()
                
                if len(parts) >= 4 and parts[2] == ip_destino and parts[3] == mascara_d:
                    if objeto_nome_d:  
                        add_exists_d.append({
                            'ip_destino': ip_destino,
                            'prefixo_d': prefixo_d,
                            'mascara_d': mascara_d,
                            'objeto_nome_d': objeto_nome_d,
                            'zona_ou_interface': zones_d.get('zone_name_d', zones_d.get('interface_name_d'))
                        })
                        break  

        if not any(d['ip_destino'] == ip_destino for d in add_exists_d):
            objeto_nome_d = f"H_{ip_destino}/{prefixo_d}" if prefixo_d == "32" else f"N_{ip_destino}/{prefixo_d}"
            nova_entrada = {
                'ip_destino': ip_destino,
                'prefixo_d': prefixo_d,
                'mascara_d': mascara_d,
                'objeto_nome_d': objeto_nome_d,
                'zona_ou_interface': zones_d.get('zone_name_d', zones_d.get('interface_name_d'))
            }
            add_create_d.append(nova_entrada)

    return add_exists_d, add_create_d


#######################################################################  PORTA/PROTOCOLO  #############################################################################

protocolos_portas = { 
    "http": {"porta": 80, "protocolo": "tcp"},
    "https": {"porta": 443, "protocolo": "tcp"},
    "ftp": {"porta": 21, "protocolo": "tcp"},
    "ssh": {"porta": 22, "protocolo": "tcp"},
    "telnet": {"porta": 23, "protocolo": "tcp"},
    "dns": {"porta": 53, "protocolo": "tcp/udp"}, 
    "smtp": {"porta": 25, "protocolo": "tcp"},
    "pop3": {"porta": 110, "protocolo": "tcp"},
    "imap": {"porta": 143, "protocolo": "tcp"},
    "imaps": {"porta": 993, "protocolo": "tcp"},
    "smtps": {"porta": 465, "protocolo": "tcp"},
    "pop3s": {"porta": 995, "protocolo": "tcp"},
    "tftp": {"porta": 69, "protocolo": "udp"},
    "rdp": {"porta": 3389, "protocolo": "tcp"},
    "ldap": {"porta": 389, "protocolo": "tcp/udp"},
    "ldaps": {"porta": 636, "protocolo": "tcp"},
    "snmp": {"porta": 161, "protocolo": "udp"},
    "bgp": {"porta": 179, "protocolo": "tcp"},
    "ntp": {"porta": 123, "protocolo": "udp"},
    "sip": {"porta": 5060, "protocolo": "tcp/udp"},  
    "smb": {"porta": 445, "protocolo": "tcp"},
    "nfs": {"porta": 2049, "protocolo": "tcp/udp"},  
    "oracle": {"porta": 1521, "protocolo": "tcp"},
    "ping": {"porta": "8", "protocolo": "icmptype"},
}


def process_portas(portas):
    if not portas:
        print("Aviso: Nenhuma porta fornecida ou valor inválido (valor é None ou vazio).")
        return []

    if isinstance(portas, (int, float)):
        portas = str(int(portas)) 

    if not isinstance(portas, str):
        print(f"Aviso: Tipo inválido para 'portas'. Esperado 'str', mas recebido '{type(portas).__name__}'.")
        return []

    portas = portas.strip()

    if not portas:  
        print("Aviso: Nenhuma porta fornecida ou valor inválido (apenas espaços).")
        return []

    portas = portas.strip()  
    if ',' not in portas:
        portas_list = [portas.strip()]
    else:
        portas_list = portas.split(',')

    porta_info = []

    for index, porta in enumerate(portas_list, start=1):
        porta = porta.strip()
        if not porta: 
            continue
        
        protocolos = []
        porta_inicial = porta_final = None

        if '/' in porta:
            partes = porta.split('/')
            porta = partes[0]
            protocolos = partes[1:]
            protocolos = [p.lower() for p in protocolos]

        elif porta.isalpha():  
            porta = porta.lower()
            if porta in protocolos_portas:
                porta_inicial = protocolos_portas[porta]["porta"]
                porta_final = porta_inicial
                protocolos = [protocolos_portas[porta]["protocolo"]]
            else:
                print(f"Aviso: Porta {porta} não encontrada no dicionário 'protocolos_portas'.")
        elif porta.isdigit():  
            porta_num = int(porta)
            for dados in protocolos_portas.values():
                if dados["porta"] == porta_num:
                    porta_inicial = porta_final = porta_num
                    protocolos = [dados["protocolo"]]
                    break
            else:
                porta_inicial = porta_final = porta_num
                protocolos = ['tcp']

        if '-' in porta:
            porta_inicial, porta_final = map(int, porta.split('-'))
        elif porta.isdigit():
            porta_inicial = porta_final = int(porta)

        if porta_inicial is None:
            porta_inicial = ''
        if porta_final is None:
            porta_final = porta_inicial

        porta_info.append({
            'nome': f'porta_{index}',
            'porta_inicial': porta_inicial,
            'porta_final': porta_final,
            'protocolos': protocolos
        })

    return porta_info



def check_service(net_connect, portas):
    portas_create = []  
    portas_exists = [] 

    if not portas:
        print("Nenhuma porta fornecida ou valor inválido.")
        return portas_exists, portas_create

    for entry in portas:
        nome = entry.get('nome')
        porta_inicial = entry.get('porta_inicial')
        porta_final = entry.get('porta_final')
        protocolos = entry.get('protocolos')

        if porta_inicial == "/" or porta_final == "/":
            print(f"Pulando serviço {nome} com porta '/'.")
            continue

        for protocolo in protocolos:
            protocolo = protocolo.lower()

            if "tcp/udp" in protocolo:
                protocolos_separados = ["tcp", "udp"]
                for prot in protocolos_separados:
                    if porta_inicial == porta_final:
                        command = f"show firewall service custom | grep '{porta_inicial}'"
                        output_porta = net_connect.send_command(command)
                        if output_porta:
                            if any(re.search(rf"{prot}-portrange\s+\b{porta_inicial}\b", line) for line in output_porta.splitlines()):
                                portas_exists.append(entry)
                            else:
                                portas_create.append(entry)
                    else:
                        command = f"show firewall service custom | grep '{porta_inicial}-{porta_final}'"
                        output_porta = net_connect.send_command(command)
                        if output_porta:
                            if any(re.search(rf"{protocolo}-portrange\s+\b{porta_inicial}\b-\b{porta_final}\b", line) for line in output_porta.splitlines()):
                                portas_exists.append(entry)
                            else:
                                portas_create.append(entry)

            else:
                if porta_inicial == porta_final:
                    command = f"show firewall service custom | grep '{porta_inicial}'"
                    output_porta = net_connect.send_command(command)
                    if output_porta:
                        if any(re.search(rf"{protocolo}-portrange\s+\b{porta_inicial}\b", line) for line in output_porta.splitlines()):
                            portas_exists.append(entry)
                        else:
                            portas_create.append(entry)
                else:
                    command = f"show firewall service custom | grep '{porta_inicial}-{porta_final}'"
                    output_porta = net_connect.send_command(command)
                    if output_porta:
                        if any(re.search(rf"{protocolo}-portrange\s+\b{porta_inicial}\b-\b{porta_final}\b", line) for line in output_porta.splitlines()):
                            portas_exists.append(entry)
                        else:
                            portas_create.append(entry)

    return portas_exists, portas_create



########################################################################### POLICY #################################################################################

def check_policy(net_connect, origem_list, destino_list, porta_info):
    policy_create = []
    policy_exists = []

    if not net_connect:
        raise ConnectionError("Falha ao conectar ao firewall")

    print("Iniciando verificação de políticas...")

    for origem_entry in origem_list:
        if isinstance(origem_entry, dict):
            ip_origem = origem_entry.get('ip_origem', 'IP_Origem_Indefinido')
            porta_origem = 0  
            
            interface_name_o = origem_entry.get('interface_name_o', 'Interface_Indefinida')
            if isinstance(interface_name_o, list):
                interface_name_o = interface_name_o[0]  

            zones_o = {
                'zona_name_o': origem_entry.get('zona_name_o', 'Zona_Indefinida'),
                'interface_name_o': interface_name_o
            }
            
            for destino_entry in destino_list:
                if isinstance(destino_entry, dict):
                    ip_destino = destino_entry.get('ip_destino', 'IP_Destino_Indefinido').strip()
                    zones_d = {
                        'zona_name_d': destino_entry.get('zona_name_d', 'Zona_Indefinida'),
                        'interface_name_d': destino_entry.get('interface_name_d', 'Interface_Indefinida')
                    }

                    for porta in porta_info:
                        porta_inicial = porta.get('porta_inicial', None)
                        porta_final = porta.get('porta_final', porta_inicial)
                        protocolos = porta.get('protocolos', [])

                        if not isinstance(protocolos, list):
                            protocolos = [protocolos]

                        for protocolo in protocolos:
                            if porta_inicial is not None and porta_inicial != "":
                                porta_destino = f"{porta_inicial}-{porta_final}" if porta_inicial != porta_final else porta_inicial
                                command = f"diagnose firewall iprope lookup {ip_origem} {porta_origem} {ip_destino} {porta_destino} {protocolo} {zones_o['interface_name_o']}\n"
                                print(command)

                                try:
                                    output_policy = net_connect.send_command(command)
                                    print(f"Saída do comando para {ip_origem} e {ip_destino}: {output_policy}")

                                    if re.search(r"matches\s+policy\s+id:\s+0", output_policy, re.IGNORECASE) or "No policy" in output_policy:
                                        print(f"Nenhuma política encontrada para {ip_origem} -> {ip_destino}")
                                        policy_create.append({
                                            'ip_origem': ip_origem,
                                            'porta_origem': porta_origem,
                                            'ip_destino': ip_destino,
                                            'porta_destino': porta_destino,
                                            'protocolo': protocolo,
                                            'zones_d': zones_d,
                                            'zones_o': zones_o
                                        })
                                        print(f"Política precisa ser criada para {ip_origem} -> {ip_destino}")
                                    elif "matches policy id:" in output_policy:
                                        policy_ids = re.findall(r"matches policy id:\s*(\d+)", output_policy)
                                        valid_policy_ids = [policy_id for policy_id in policy_ids if policy_id != "0"]

                                        if valid_policy_ids:
                                            for policy_id in valid_policy_ids:
                                                print(f"Política existente detectada: ID {policy_id}")
                                                policy_exists.append({
                                                    'ip_origem': ip_origem,
                                                    'porta_origem': porta_origem,
                                                    'ip_destino': ip_destino,
                                                    'porta_destino': porta_destino,
                                                    'protocolo': protocolo,
                                                    'zones_d': zones_d,
                                                    'zones_o': zones_o,
                                                    'policy_id': policy_id
                                                })
                                        else:
                                            print(f"Nenhuma política válida encontrada para {ip_origem} -> {ip_destino}. IDs detectados: {policy_ids}")
                                            policy_create.append({
                                            'ip_origem': ip_origem,
                                            'porta_origem': porta_origem,
                                            'ip_destino': ip_destino,
                                            'porta_destino': porta_destino,
                                            'protocolo': protocolo,
                                            'zones_d': zones_d,
                                            'zones_o': zones_o
                                        })
                                except Exception as e:
                                    print(f"Erro ao extrair o(s) ID(s) da política: {e}")
        else:
            raise TypeError(f"Esperado um dicionário para 'origem_entry', mas recebeu: {type(origem_entry)}")

    print("CheckPolicy finalizado")
    return policy_create, policy_exists



#################################################################### SCRIPTS TO CREATE #############################################################################

def create_address_script_o(add_create_o):
    scripts_a_o = [] 
    enderecos_origem = set()  

    scripts_a_o.append("config firewall address\n")
    
    for entry in add_create_o:
        ip_origem = entry['ip_origem']
        prefixo_o = entry['prefixo_o']
        objeto_nome_o = entry['objeto_nome_o']

        if (objeto_nome_o, ip_origem, prefixo_o) not in enderecos_origem:
            enderecos_origem.add((objeto_nome_o, ip_origem, prefixo_o))
            scripts_a_o.append(f"edit \"{objeto_nome_o}\"\n")
            scripts_a_o.append(f"set subnet {ip_origem}/{prefixo_o}\n")
            scripts_a_o.append("next\n")
    
    scripts_a_o.append("end\n")
    
    print("Script de criação de address origem finalizado")
    return ''.join(scripts_a_o)



def create_address_script_d(add_create_d):
    scripts_a_d = []
    enderecos_destino = set()  
    
    scripts_a_d.append("config firewall address\n")
    
    for entry in add_create_d:
        ip_destino = entry['ip_destino']
        prefixo_d = entry['prefixo_d']
        objeto_nome_d = entry['objeto_nome_d']

        if (objeto_nome_d, ip_destino, prefixo_d) not in enderecos_destino:
            enderecos_destino.add((objeto_nome_d, ip_destino, prefixo_d))
            scripts_a_d.append(f"edit \"{objeto_nome_d}\"\n")
            scripts_a_d.append(f"set subnet {ip_destino}/{prefixo_d}\n")
            scripts_a_d.append("next\n")
    
    scripts_a_d.append("end\n")
    
    print("Script de criação de address destino finalizado")
    return ''.join(scripts_a_d)



def create_service_script(portas_create):
    scripts_p = []
    servicos = set()  
    
    scripts_p.append("config firewall service custom\n")
    
    for entry in portas_create:
        for protocolo in entry['protocolos']:
            if entry['porta_inicial'] is not None and entry['porta_inicial'] == entry['porta_final']:
                servico = (protocolo, entry['porta_inicial'])
                if servico not in servicos:
                    servicos.add(servico)
                    scripts_p.append(f"edit \"{protocolo}_{entry['porta_inicial']}\"\n") 
                    scripts_p.append(f"set {protocolo.lower()}-portrange {entry['porta_inicial']}\n")
                    scripts_p.append("next\n")
            elif entry['porta_inicial'] is not None:  
                servico = (protocolo, entry['porta_inicial'], entry['porta_final'])
                if servico not in servicos:
                    servicos.add(servico)
                    scripts_p.append(f"edit \"{protocolo}_{entry['porta_inicial']}-{entry['porta_final']}\"\n")
                    scripts_p.append(f"set {protocolo.lower()}-portrange {entry['porta_inicial']}-{entry['porta_final']}\n")
                    scripts_p.append("next\n")
    
    scripts_p.append("end\n")
    
    print("Script de criação de serviços finalizado")
    return ''.join(scripts_p)



def script_policy(policy_create, policy_exists):
    script_output = []

    print("\nGerando script para as políticas...")

    if policy_create:
        print(f"{len(policy_create)} políticas precisam ser criadas:")
        for policy in policy_create:
            ip_origem = policy['ip_origem']
            porta_origem = policy['porta_origem']
            ip_destino = policy['ip_destino']
            porta_destino = policy['porta_destino']
            protocolo = policy['protocolo']
            zones_d = policy['zones_d']
            zones_o = policy['zones_o']

            srcintf = zones_o.get('zone_name_o') or zones_o.get('interface_name_o', '')
            dstintf = zones_d.get('zone_name_d') or zones_d.get('interface_name_d', '')

            script_output.append(
                f"edit 0\n"
                f"set srcaddr \"{ip_origem}\"\n"
                f"set dstaddr \"{ip_destino}\"\n"
                f"set srcintf \"{srcintf}\"\n"
                f"set dstintf \"{dstintf}\"\n"
                f"set service \"{protocolo}\"\n"
                f"set schedule always\n"
                f"set action accept\n" 
                f"next\n"
            )
            print(f"Política criada para {ip_origem} -> {ip_destino} ({porta_destino}/{protocolo})")

    if policy_exists:
        print(f"{len(policy_exists)} políticas já existentes foram encontradas:")
        for policy in policy_exists:
            ip_origem = policy['ip_origem']
            porta_origem = policy['porta_origem']
            ip_destino = policy['ip_destino']
            porta_destino = policy['porta_destino']
            protocolo = policy['protocolo']
            policy_id = policy['policy_id']

            script_output.append(
                f"# Política já existente (ID: {policy_id})\n"
                f"# Origem: {ip_origem}, Destino: {ip_destino}, Porta: {porta_destino}, Protocolo: {protocolo}\n"
            )
            print(f"Política existente com ID {policy_id} para {ip_origem} -> {ip_destino} ({porta_destino}/{protocolo})")

    if not policy_create and not policy_exists:
        print("Nenhuma política foi criada ou encontrada.")

    print("\nScript gerado com sucesso.")
    return "\n".join(script_output)



######################################################################  GERANDO ARQUIVO TEXTO #######################################################################

def gerar_script_bonitinho(scripts_p, scripts_a_d, scripts_a_o, policy_script):
    script_auto_fw = "##  Script para o firewall ##\n"

    if scripts_a_o.strip():
        script_auto_fw += "\n## Endereços de Origem ##\n"
        script_auto_fw += scripts_a_o

    if scripts_a_d.strip():
        script_auto_fw += "\n\n## Endereços de Destino ##\n"
        script_auto_fw += scripts_a_d

    if scripts_p.strip():
        script_auto_fw += "\n\n## Portas ##\n"
        script_auto_fw += scripts_p

    if policy_script.strip():
        script_auto_fw += "\n\n## Policy ##\n"
        script_auto_fw += policy_script

    return script_auto_fw



def salvar(script_auto_fw, linha_excel=None):
    try:
        file_path = r"C:\Users\bianca.bondan\OneDrive\Documents\SCRIPTS\AUTOMAÇÃO - FIREWALL\script_auto_fw.txt"
        if linha_excel is not None:
            separador = f"\n\n--------------- Linha Excel {linha_excel + 1} -----------------------\n\n"
        else:
            separador = ""

        with open(file_path, "a", encoding="utf-8") as file:
            file.write(separador)
            file.write(script_auto_fw)

        print(f"Script salvo com sucesso em: {file_path}")
    except Exception as e:
        print(f"Erro ao salvar o arquivo: {str(e)}")


##########################################################################################################################

def processar_linhas(caminho_excel):
    if not os.path.exists(caminho_excel):
        print(f"Erro: O arquivo '{caminho_excel}' não foi encontrado.")
        return
    
    try:
        if caminho_excel.endswith('.csv'):
            df = pd.read_csv(caminho_excel)
        elif caminho_excel.endswith(('.xls', '.xlsx')):
            df = pd.read_excel(caminho_excel)
        else:
            print("Erro: O arquivo fornecido não é suportado. Use um arquivo .csv, .xls ou .xlsx.")
            return
    except Exception as e:
        print(f"Erro ao ler o arquivo: {e}")
        traceback.print_exc()
        return

    for index, row in df.iterrows():
        origem = row.get('ORIGEM')
        destino = row.get('DESTINO')
        portas = row.get('PORTAS')  
        fw = row.get('FIREWALL')
        
        if not origem or not destino:
            print(f"Erro: 'ORIGEM' ou 'DESTINO' ou 'PORTAS' OU 'FIREWALL' está vazio na linha  {index + 1}")
            continue
        
        fw = str(row.get('FIREWALL', '')).strip()

        if not fw or fw.lower() == 'nan':
            print(f"Erro: Firewall inválido na linha {index + 1}")
            continue
        
        try:
            fw_list = [ip_fw.strip() for ip_fw in fw.split(',')]
        except AttributeError:
            print(f"Erro ao processar o FIREWALL na linha {index + 1}")
            continue

        if not origem or not destino or not portas or not fw:
            print(f"Erro: 'ORIGEM', 'DESTINO', 'PORTAS' ou 'FIREWALL' está vazio na linha {index + 1}")
            continue
        
        for ip_fw in fw_list:
            try:
                print(f"Tentando conectar ao firewall: {fw}")
                net_connect = conectar_fW(ip_fw)

                origem_list = process_origem(origem)
                origem_list = add_zones_to_o(net_connect, origem_list)

                for origem_data in origem_list:
                    ip_origem = origem_data.get('ip_origem')
                    prefixo_o = origem_data.get('prefixo_o')
                    mascara_o = origem_data.get('mascara_o')

                    if ip_origem and prefixo_o and mascara_o:
                        add_exists_o, add_create_o = check_address_o(net_connect, [origem_data])
                        zones_o = check_routing_o(net_connect, ip_origem)
                        
                        if zones_o:
                            origem_data['zone_names_o'] = [zone['zone_name_o'] for zone in zones_o if zone['zone_name_o']]
                            origem_data['interfaces_o'] = [zone['interface_name_o'] for zone in zones_o]
                    else:
                        print(f"Dados de origem incompletos na linha {index + 1}")


                        
                    destino_list = process_destino(destino)
                    destino_list = add_zones_to_d(net_connect, destino_list)

                    for destino_data in destino_list:
                        ip_destino = destino_data.get('ip_destino')
                        prefixo_d = destino_data.get('prefixo_d')
                        mascara_d = destino_data.get('mascara_d')

                        if ip_destino and prefixo_d and mascara_d:
                            add_exists_d, add_create_d = check_address_d(net_connect, [destino_data])
                            zones_d = check_routing_d(net_connect, ip_destino)
                            
                            if zones_d:
                                destino_data['zone_names_d'] = [zone['zone_name_d'] for zone in zones_d if zone['zone_name_d']]
                                destino_data['interfaces_d'] = [zone['interface_name_d'] for zone in zones_d]
                        else:
                            print(f"Dados de destino incompletos na linha {index + 1}")



                porta_info = process_portas(portas)
                portas_exists, portas_create = check_service(net_connect, porta_info)


                policy_create, policy_exists = check_policy(net_connect, origem_list, destino_list, porta_info)
                print("Policy processadas")

                scripts_a_o = create_address_script_o(add_create_o)
                scripts_a_d = create_address_script_d(add_create_d)
                scripts_p = create_service_script(portas_create)
                policy_script = script_policy(policy_create, policy_exists)

                script_auto_fw = gerar_script_bonitinho(scripts_p, scripts_a_d, scripts_a_o, policy_script)
                
                salvar(script_auto_fw, index)

            except Exception as e:
                print(f"Falha ao conectar ao firewall {ip_fw}: {str(e)}")
                traceback.print_exc()

print("Certifique que as colunas do arquivo sejam ORIGEM, DESTINO, PORTAS, FIREWALL.")
caminho_excel = input("Por favor, insira o caminho do arquivo Excel ou CSV: ")
processar_linhas(caminho_excel)
