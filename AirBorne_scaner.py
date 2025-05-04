#!/usr/bin/env python3

import sys
import socket
import time
import re
import requests
from zeroconf import ServiceBrowser, Zeroconf
from colorama import Fore, Style, init

init()

class Colors:
    VULNERABLE = Fore.RED + Style.BRIGHT
    POTENTIAL = Fore.YELLOW + Style.BRIGHT
    SAFE = Fore.GREEN + Style.BRIGHT
    ENDC = Style.RESET_ALL

class AirPlayDetector:
    def __init__(self):
        self.devices = {}
        self.vulnerable_versions = ["2.7.1", "3.6.0.126"]

    def extract_version(self, response_text):
        # Utilizamos una E.R. para encontrar la versión en el formato "AirPlay;X.X.X.X"
        match = re.search(r"AirPlay;(\d+\.\d+\.\d+\.\d+)", response_text)
        if match:
            return match.group(1)
        return "Versión desconocida"

    def version_to_numbers(self, version):
        try:
            return [int(x) for x in version.split('.')]
        except:
            return []

    def vulnerability_status(self, version):

        if version == "Versión desconocida":
            return "Potencialmente vulnerable"
        ver_nums = self.version_to_numbers(version)
        if not ver_nums:
            return "Potencialmente vulnerable"
        for safe_version in self.vulnerable_versions:
            safe_nums = self.version_to_numbers(safe_version)
            if ver_nums < safe_nums:
                return "Vulnerable"
        return "No vulnerable"

    def fetch_info(self, ip, port=7000):
        try:
            url = f"http://{ip}:{port}/info"
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                return response.text
            return None
        except requests.RequestException:
            return None

    def discover_mdns(self):
        print(f"{Fore.MAGENTA}Buscando dispositivos AirPlay usando mDNS...{Style.RESET_ALL}")

        class Listener:
            def __init__(self, detector):
                self.detector = detector

            def add_service(self, zeroconf, type_, name):
                info = zeroconf.get_service_info(type_, name)
                if info:
                    ips = [socket.inet_ntoa(addr) for addr in info.addresses]
                    for ip in ips:
                        if ip not in self.detector.devices:
                            response = self.detector.fetch_info(ip)
                            version = self.detector.extract_version(response) if response else "Versión desconocida"
                            status = self.detector.vulnerability_status(version)

                            self.detector.devices[ip] = {
                                "ip": ip,
                                "hostname": info.server,
                                "version": version,
                                "status": status
                            }

            def update_service(self, *args):
                # Método requerido por zeroconf
                pass

        zeroconf = Zeroconf()
        listener = Listener(self)
        ServiceBrowser(zeroconf, "_airplay._tcp.local.", listener)
        ServiceBrowser(zeroconf, "_raop._tcp.local.", listener)
        time.sleep(3)
        zeroconf.close()

    def print_results(self):
        if not self.devices:
            print(f"{Fore.YELLOW}No se encontraron dispositivos AirPlay.{Style.RESET_ALL}")
            return

        # Clasificamos dispositivos según su estado
        vulnerable_devices = [d for d in self.devices.values() if d["status"] == "Vulnerable"]
        potential_devices = [d for d in self.devices.values() if d["status"] == "Potencialmente vulnerable"]
        safe_devices = [d for d in self.devices.values() if d["status"] == "No vulnerable"]

        def print_devices(devices, title, color):
            if devices:
                print(f"\n{color}{title}:{Style.RESET_ALL}")
                print("-" * 50)
                for d in devices:
                    print(f"{color}Dispositivo:{Style.RESET_ALL} {d['hostname'] or 'Desconocido'}")
                    print(f"{Fore.MAGENTA}IP:{Style.RESET_ALL} {d['ip']}")
                    print(f"{Fore.MAGENTA}Versión:{Style.RESET_ALL} {d['version']}")
                    print(f"{color}Estado:{Style.RESET_ALL} {d['status']}")
                    print("-" * 50)

        print_devices(vulnerable_devices, "DISPOSITIVOS VULNERABLES ENCONTRADOS", Colors.VULNERABLE)
        print_devices(potential_devices, "DISPOSITIVOS POTENCIALMENTE VULNERABLES", Colors.POTENTIAL)
        print_devices(safe_devices, "DISPOSITIVOS SEGUROS", Colors.SAFE)

def main():
    import argparse
    import json
    parser = argparse.ArgumentParser(description="Detector simple de dispositivos AirPlay vulnerables")
    parser.add_argument("-o", "--output", help="Archivo JSON para guardar los resultados")
    args = parser.parse_args()

    print(f"""{Fore.MAGENTA}Escaner apra la vulnerabilidad AirBorne{Style.RESET_ALL}
{Fore.YELLOW}Úsese esta herramienta solo en redes autorizadas.{Style.RESET_ALL}
""")

    detector = AirPlayDetector()
    detector.discover_mdns()
    detector.print_results()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(detector.devices, f, indent=4)
        print(f"{Fore.GREEN}Resultados guardados en {args.output}{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        import zeroconf
        import colorama
        import requests
    except ImportError:
        print("Por favor, instale las dependencias con: pip install -r requirements.txt")
        sys.exit(1)
    main()
