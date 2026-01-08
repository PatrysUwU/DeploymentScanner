#!/usr/bin/env python3
"""
Docker Compose Scanner - Analizuje dystrybucję kodu w kontenerach
Autor: DeploymentScanner
"""

import yaml
import os
import sys
import re
from pathlib import Path
from typing import Dict, List, Any, Set
import argparse
from dataclasses import dataclass, field


@dataclass
class ServiceInfo:
    """Informacje o serwisie Docker Compose"""
    name: str
    image: str = "custom"
    build_context: str = None
    dockerfile: str = None
    volumes: List[Dict] = field(default_factory=list)
    ports: List[str] = field(default_factory=list)
    environment: Dict[str, str] = field(default_factory=dict)
    depends_on: List[str] = field(default_factory=list)
    command: str = None
    source_files: List[Dict] = field(default_factory=list)
    mounted_code: List[Dict] = field(default_factory=list)
    dockerfile_instructions: List[Dict] = field(default_factory=list)


class DockerComposeScanner:
    """Scanner plików Docker Compose"""

    def __init__(self):
        self.services: Dict[str, ServiceInfo] = {}
        self.volumes: Dict[str, Dict] = {}
        self.networks: Dict[str, Dict] = {}
        self.base_path: Path = Path(".")

        # Rozszerzenia plików kodu
        self.code_extensions = {
            '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.php', '.go',
            '.rb', '.cpp', '.c', '.cs', '.html', '.css', '.scss', '.vue',
            '.sql', '.sh', '.yaml', '.yml', '.json', '.xml'
        }

        # Katalogi do pominięcia
        self.ignore_dirs = {
            'node_modules', '.git', '.vscode', '__pycache__', '.pytest_cache',
            'dist', 'build', 'target', 'bin', 'obj', '.idea', 'venv', 'env'
        }

    def scan_docker_compose(self, yaml_path: str) -> Dict[str, Any]:
        """Główna funkcja skanowania pliku docker-compose.yml"""
        print(f"Skanowanie Docker Compose: {yaml_path}")

        yaml_path = Path(yaml_path)
        self.base_path = yaml_path.parent

        try:
            with open(yaml_path, 'r', encoding='utf-8') as file:
                compose_data = yaml.safe_load(file)
        except FileNotFoundError:
            raise FileNotFoundError(f"Plik {yaml_path} nie został znaleziony")
        except yaml.YAMLError as e:
            raise ValueError(f"Błąd parsowania YAML: {e}")

        if not compose_data.get('services'):
            raise ValueError("Brak sekcji 'services' w pliku docker-compose.yml")

        # Analizuj poszczególne komponenty
        self._analyze_services(compose_data.get('services', {}))
        self._analyze_volumes(compose_data.get('volumes', {}))
        self._analyze_networks(compose_data.get('networks', {}))

        # Generuj raport
        self._generate_report()

        return {
            'services': {name: self._service_to_dict(service)
                        for name, service in self.services.items()},
            'volumes': self.volumes,
            'networks': self.networks,
            'summary': self._generate_summary()
        }

    def _analyze_services(self, services: Dict[str, Any]):
        """Analizuje wszystkie serwisy w docker-compose.yml"""
        print(f"\nAnaliza {len(services)} serwisów...\n")

        for service_name, config in services.items():
            print(f"Analizuję serwis: {service_name}")

            service_info = ServiceInfo(name=service_name)

            # Podstawowe informacje
            service_info.image = config.get('image', 'custom')
            service_info.command = config.get('command')
            service_info.depends_on = config.get('depends_on', [])

            # Analiza build context
            if 'build' in config:
                self._analyze_build_context(service_info, config['build'])

            # Analiza volumes
            if 'volumes' in config:
                self._analyze_service_volumes(service_info, config['volumes'])

            # Analiza portów
            if 'ports' in config:
                self._analyze_service_ports(service_info, config['ports'])

            # Analiza zmiennych środowiskowych
            if 'environment' in config:
                self._analyze_environment(service_info, config['environment'])

            self.services[service_name] = service_info

    def _analyze_build_context(self, service_info: ServiceInfo, build_config: Any):
        """Analizuje konfigurację build"""
        if isinstance(build_config, str):
            build_context = build_config
            dockerfile = "Dockerfile"
        elif isinstance(build_config, dict):
            build_context = build_config.get('context', '.')
            dockerfile = build_config.get('dockerfile', 'Dockerfile')
        else:
            return

        service_info.build_context = build_context
        service_info.dockerfile = dockerfile

        # Pełna ścieżka do build context
        build_path = self.base_path / build_context
        dockerfile_path = build_path / dockerfile

        print(f"   Build context: {build_context}")
        print(f"   Dockerfile: {dockerfile}")

        # Analizuj Dockerfile jeśli istnieje
        if dockerfile_path.exists():
            self._analyze_dockerfile(service_info, dockerfile_path)
        else:
            print(f"    Dockerfile nie znaleziony: {dockerfile_path}")

        # Skanuj kod źródłowy w build context
        self._scan_source_code(service_info, build_path)

    def _analyze_dockerfile(self, service_info: ServiceInfo, dockerfile_path: Path):
        """Analizuje instrukcje w Dockerfile"""
        try:
            with open(dockerfile_path, 'r', encoding='utf-8') as file:
                lines = file.readlines()

            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Instrukcje COPY/ADD
                if line.startswith(('COPY', 'ADD')):
                    parts = line.split()
                    if len(parts) >= 3:
                        service_info.dockerfile_instructions.append({
                            'type': parts[0],
                            'source': parts[1],
                            'destination': parts[2],
                            'line': line_num,
                            'instruction': line
                        })

                # Instrukcja EXPOSE
                elif line.startswith('EXPOSE'):
                    ports = line.split()[1:]
                    service_info.ports.extend(ports)

                # Instrukcja ENV
                elif line.startswith('ENV'):
                    env_part = line[3:].strip()
                    if '=' in env_part:
                        key, value = env_part.split('=', 1)
                        service_info.environment[key.strip()] = value.strip()

        except Exception as e:
            print(f"    Błąd analizy Dockerfile: {e}")

    def _scan_source_code(self, service_info: ServiceInfo, build_path: Path):
        """Skanuje pliki kodu źródłowego w build context"""
        if not build_path.exists():
            return

        source_files = []

        try:
            for file_path in self._find_source_files(build_path):
                relative_path = file_path.relative_to(build_path)
                source_files.append({
                    'path': str(relative_path),
                    'full_path': str(file_path),
                    'extension': file_path.suffix,
                    'size': file_path.stat().st_size if file_path.exists() else 0
                })

            service_info.source_files = source_files
            print(f"   Znaleziono {len(source_files)} plików kodu")

        except Exception as e:
            print(f"    Błąd skanowania kodu: {e}")

    def _find_source_files(self, directory: Path) -> List[Path]:
        """Znajduje pliki kodu źródłowego rekursywnie"""
        source_files = []

        def scan_directory(path: Path):
            if not path.is_dir() or path.name in self.ignore_dirs:
                return

            try:
                for item in path.iterdir():
                    if item.is_file() and item.suffix.lower() in self.code_extensions:
                        source_files.append(item)
                    elif item.is_dir():
                        scan_directory(item)
            except PermissionError:
                pass

        scan_directory(directory)
        return source_files

    def _analyze_service_volumes(self, service_info: ServiceInfo, volumes: List[Any]):
        """Analizuje volumes serwisu"""
        for volume in volumes:
            volume_info = self._parse_volume(volume)
            if volume_info:
                service_info.mounted_code.append(volume_info)

    def _parse_volume(self, volume: Any) -> Dict[str, Any]:
        """Parsuje definicję volume"""
        if isinstance(volume, str):
            # Format: "host:container" lub "host:container:mode"
            parts = volume.split(':')
            if len(parts) >= 2:
                host_path = parts[0]
                container_path = parts[1]
                mode = parts[2] if len(parts) > 2 else 'rw'

                return {
                    'type': 'bind_mount',
                    'host_path': str(self.base_path / host_path) if not os.path.isabs(host_path) else host_path,
                    'container_path': container_path,
                    'mode': mode,
                    'is_code': self._is_code_path(host_path)
                }

        elif isinstance(volume, dict):
            # Long format
            source = volume.get('source', '')
            target = volume.get('target', '')
            read_only = volume.get('read_only', False)

            return {
                'type': 'volume_mount',
                'host_path': str(self.base_path / source) if source and not os.path.isabs(source) else source,
                'container_path': target,
                'mode': 'ro' if read_only else 'rw',
                'is_code': self._is_code_path(source)
            }

        return None

    def _is_code_path(self, path: str) -> bool:
        """Sprawdza czy ścieżka prawdopodobnie zawiera kod"""
        code_indicators = [
            '/app', '/src', '/code', './src', './app', './', '../',
            'src/', 'app/', 'lib/', 'server/', 'client/'
        ]

        path_lower = path.lower()
        return any(indicator in path_lower for indicator in code_indicators) or \
               any(ext in path_lower for ext in self.code_extensions)

    def _analyze_service_ports(self, service_info: ServiceInfo, ports: List[Any]):
        """Analizuje porty serwisu"""
        for port in ports:
            if isinstance(port, (str, int)):
                service_info.ports.append(str(port))
            elif isinstance(port, dict):
                target = port.get('target', '')
                published = port.get('published', '')
                if target:
                    service_info.ports.append(f"{published}:{target}" if published else str(target))

    def _analyze_environment(self, service_info: ServiceInfo, environment: Any):
        """Analizuje zmienne środowiskowe"""
        if isinstance(environment, list):
            for env in environment:
                if isinstance(env, str) and '=' in env:
                    key, value = env.split('=', 1)
                    service_info.environment[key] = value
        elif isinstance(environment, dict):
            service_info.environment.update(environment)

    def _analyze_volumes(self, volumes: Dict[str, Any]):
        """Analizuje definicje volumes"""
        self.volumes = volumes

    def _analyze_networks(self, networks: Dict[str, Any]):
        """Analizuje definicje networks"""
        self.networks = networks

    def _generate_report(self):
        """Generuje szczegółowy raport"""
        print('\n' + '=' * 80)
        print('RAPORT DYSTRYBUCJI KODU W KONTENERACH')
        print('=' * 80)

        for service_name, service in self.services.items():
            self._print_service_report(service)

        print('\n' + '=' * 80)
        print('PODSUMOWANIE')
        print('=' * 80)

        summary = self._generate_summary()
        print(f"Łączna liczba kontenerów: {summary['total_services']}")
        print(f"Wolumeny: {summary['total_volumes']}")
        print(f"Sieci: {summary['total_networks']}")
        print(f"Łączna liczba plików kodu: {summary['total_source_files']}")
        print(f"Zamontowane ścieżki z kodem: {summary['total_mounted_code']}")

    def _print_service_report(self, service: ServiceInfo):
        """Drukuje raport dla pojedynczego serwisu"""
        print(f"\nKONTENER: {service.name.upper()}")
        print('─' * 50)

        print(f"Obraz: {service.image}")
        if service.build_context:
            print(f"Build context: {service.build_context}")
            print(f"Dockerfile: {service.dockerfile}")

        # Kod źródłowy
        if service.source_files:
            print(f"\nKOD ŹRÓDŁOWY W KONTENERZE ({len(service.source_files)} plików):")
            for i, file_info in enumerate(service.source_files[:10]):
                size_kb = file_info['size'] // 1024 if file_info['size'] else 0
                print(f"   • {file_info['path']} ({size_kb} KB)")

            if len(service.source_files) > 10:
                print(f"   ... i {len(service.source_files) - 10} więcej plików")

        # Instrukcje Dockerfile
        if service.dockerfile_instructions:
            print(f"\nINSTRUKCJE KOPIOWANIA:")
            for instruction in service.dockerfile_instructions:
                print(f"   {instruction['type']}: {instruction['source']} → {instruction['destination']}")

        # Zamontowany kod
        if service.mounted_code:
            print(f"\nZAMONTOWANY KOD:")
            for mount in service.mounted_code:
                icon = '' if mount['is_code'] else ''
                print(f"   {icon} {mount['host_path']} → {mount['container_path']} ({mount['mode']})")

        # Porty
        if service.ports:
            print(f"\nPORTY: {', '.join(service.ports)}")

        # Zmienne środowiskowe
        if service.environment:
            env_count = len(service.environment)
            print(f"\nZMIENNE ŚRODOWISKOWE ({env_count}):")
            for i, (key, value) in enumerate(list(service.environment.items())[:5]):
                print(f"   • {key}={value}")
            if env_count > 5:
                print(f"   ... i {env_count - 5} więcej zmiennych")

        # Zależności
        if service.depends_on:
            print(f"\n🔗 ZALEŻY OD: {', '.join(service.depends_on)}")

    def _generate_summary(self) -> Dict[str, int]:
        """Generuje podsumowanie statystyk"""
        total_source_files = sum(len(s.source_files) for s in self.services.values())
        total_mounted_code = sum(len([m for m in s.mounted_code if m['is_code']])
                               for s in self.services.values())

        return {
            'total_services': len(self.services),
            'total_volumes': len(self.volumes),
            'total_networks': len(self.networks),
            'total_source_files': total_source_files,
            'total_mounted_code': total_mounted_code
        }

    def _service_to_dict(self, service: ServiceInfo) -> Dict[str, Any]:
        """Konwertuje ServiceInfo do dict"""
        return {
            'name': service.name,
            'image': service.image,
            'build_context': service.build_context,
            'dockerfile': service.dockerfile,
            'volumes': service.volumes,
            'ports': service.ports,
            'environment': service.environment,
            'depends_on': service.depends_on,
            'command': service.command,
            'source_files': service.source_files,
            'mounted_code': service.mounted_code,
            'dockerfile_instructions': service.dockerfile_instructions
        }


def main():
    """Funkcja główna"""
    parser = argparse.ArgumentParser(
        description='Docker Compose Scanner - Analizuje dystrybucję kodu w kontenerach'
    )
    parser.add_argument(
        'compose_file',
        nargs='?',
        default='docker-compose.yml',
        help='Ścieżka do pliku docker-compose.yml (domyślnie: docker-compose.yml)'
    )
    parser.add_argument(
        '--output', '-o',
        help='Plik wyjściowy JSON z wynikami analizy'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Szczegółowe informacje'
    )

    args = parser.parse_args()

    try:
        scanner = DockerComposeScanner()
        result = scanner.scan_docker_compose(args.compose_file)

        # Zapisz wyniki do pliku JSON jeśli podano
        if args.output:
            import json
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            print(f"\nWyniki zapisano do: {args.output}")

        print('\n✅ Skanowanie zakończone pomyślnie!')

    except Exception as e:
        print(f'\n❌ Błąd podczas skanowania: {e}')
        sys.exit(1)


if __name__ == '__main__':
    main()
