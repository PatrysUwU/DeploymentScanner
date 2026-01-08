# Moduł Aggregate - Agregacyjny Skaner Bezpieczeństwa

## Opis

Moduł `aggregate.py` zapewnia kompleksowe skanowanie bezpieczeństwa projektów zawierających kontenery Docker. Integruje różne narzędzia do analizy bezpieczeństwa:

- **Trivy**: Skanowanie obrazów Docker pod kątem luk bezpieczeństwa oraz misconfiguration
- **Bandit**: Static Application Security Testing (SAST) dla kodu Python
- **Docker Compose Scanner**: Automatyczne wyciąganie nazw obrazów z plików docker-compose

## Funkcjonalności

### 🔍 Automatyczne wykrywanie obrazów
- Skanuje projekt w poszukiwaniu plików `docker-compose.yml`
- Automatycznie wyciąga nazwy obrazów Docker do skanowania
- Obsługuje różne warianty nazw plików compose

### 🛡️ Wieloaspektowa analiza bezpieczeństwa
- **Trivy Image Scan**: Luki bezpieczeństwa w obrazach Docker
- **Trivy Misconfiguration**: Problemy konfiguracyjne w plikach infrastruktury
- **Bandit SAST**: Problemy bezpieczeństwa w kodzie źródłowym Python

### 📊 Kompleksowe raportowanie
- Szczegółowe wyniki w formacie JSON
- Podsumowanie z liczbą problemów według ważności
- Automatyczne zapisywanie wyników do pliku

## Instalacja

Upewnij się, że masz zainstalowane wymagane narzędzia:

```bash
# Trivy (lokalnie na maszynie)
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Bandit
pip install bandit

# Docker (tylko do skanowania obrazów Docker)
# Instrukcje instalacji Docker według Twojego systemu operacyjnego
```

**Uwaga:** Trivy musi być dostępne w PATH jako polecenie `trivy`. Docker jest potrzebny tylko do skanowania obrazów Docker, ale nie do uruchamiania samego Trivy.

## Użycie

### Użycie programowe

```python
from deployment_scanner.aggregate import aggregate_scan

# Podstawowe użycie
results = aggregate_scan("/path/to/project")

# Z konkretnym plikiem docker-compose
results = aggregate_scan(
    proj_path="/path/to/project",
    docker_compose_path="/path/to/docker-compose.yml"
)

# Wyświetlenie podsumowania
summary = results["summary"]
print(f"Znaleziono {summary['total_issues']} problemów")
```

### Użycie z linii komend

```bash
# Podstawowe skanowanie
python -m deployment_scanner.aggregate /path/to/project

# Z konkretnym plikiem docker-compose
python -m deployment_scanner.aggregate /path/to/project --docker-compose ./docker-compose.yml

# Z własnym plikiem wyjściowym
python -m deployment_scanner.aggregate /path/to/project --output custom_results.json
```

### Przykład użycia

```python
# Uruchom przykładowy skrypt
python backend/example_usage.py
```

## Struktura wyników

### Format JSON

```json
{
  "bandit": {
    "tool": "bandit",
    "type": "SAST",
    "results": [
      {
        "Target": "/path/to/project",
        "Type": "bandit",
        "Vulnerabilities": [
          {
            "VulnerabilityID": "B101",
            "Severity": "LOW",
            "Description": "Use of assert detected...",
            "File": "/path/to/file.py",
            "Line": 42
          }
        ]
      }
    ],
    "errors": ""
  },
  "trivy_misconfig": {
    "tool": "trivy",
    "type": "MISCONFIG_SCAN",
    "results": [
      {
        "Target": "/path/to/project",
        "Type": "misconfig",
        "Misconfigurations": [
          {
            "ID": "DS002",
            "Severity": "HIGH",
            "Title": "Root user should not be used",
            "Description": "Running containers as root...",
            "Message": "Specify USER instruction",
            "Type": "Dockerfile Security Check",
            "Status": "FAIL"
          }
        ]
      }
    ],
    "errors": ""
  },
  "trivy_images": {
    "python:3.11-alpine": {
      "tool": "trivy",
      "type": "IMAGE_SCAN",
      "results": [
        {
          "Target": "python:3.11-alpine",
          "Type": "image",
          "Vulnerabilities": [
            {
              "VulnerabilityID": "CVE-2023-1234",
              "Severity": "HIGH",
              "Title": "Buffer overflow vulnerability",
              "Description": "A buffer overflow...",
              "Package": "openssl",
              "InstalledVersion": "1.1.1",
              "FixedVersion": "1.1.2"
            }
          ]
        }
      ],
      "errors": ""
    }
  },
  "summary": {
    "total_scans": 3,
    "bandit_issues": 5,
    "trivy_misconfig_issues": 2,
    "trivy_image_vulnerabilities": 15,
    "scanned_images": 1,
    "total_issues": 22,
    "severity_breakdown": {
      "critical": 1,
      "high": 8,
      "medium": 10,
      "low": 3,
      "unknown": 0
    }
  }
}
```

### Podsumowanie

Sekcja `summary` zawiera:
- `total_scans`: Liczba przeprowadzonych skanów
- `bandit_issues`: Liczba problemów znalezionych przez Bandit
- `trivy_misconfig_issues`: Liczba problemów konfiguracyjnych
- `trivy_image_vulnerabilities`: Liczba luk w obrazach
- `scanned_images`: Liczba przeskanowanych obrazów
- `total_issues`: Całkowita liczba problemów
- `severity_breakdown`: Rozkład problemów według ważności

## Konfiguracja

### Zmienne środowiskowe

```bash
# Opcjonalnie: ścieżka do binarki trivy
export TRIVY_PATH="/custom/path/to/trivy"

# Opcjonalnie: timeout dla poleceń (w sekundach)
export SCAN_TIMEOUT="300"
```

### Wykluczenia

Moduł automatycznie pomija:
- Obrazy oznaczone jako "custom" (zbudowane lokalnie bez konkretnej nazwy)
- Standardowe katalogi jak `node_modules`, `.git`, `__pycache__`
- Pliki tymczasowe i cache

## Obsługa błędów

- Błędy skanowania poszczególnych obrazów nie przerywają całego procesu
- Błędy są logowane i zapisywane w sekcji `errors` wyników
- Kontynuacja skanowania mimo problemów z pojedynczymi komponentami

## Integracja z CI/CD

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v3
        with:
          python-version: '3.11'
          
      - name: Install dependencies
        run: |
          pip install bandit
          curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
          
      - name: Run security scan
        run: |
          python -m deployment_scanner.aggregate .
          
      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: security-scan-results
          path: security_scan_results.json
```

### GitLab CI

```yaml
security_scan:
  stage: test
  image: python:3.11
  before_script:
    - pip install bandit
    - curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
  script:
    - python -m deployment_scanner.aggregate .
  artifacts:
    paths:
      - security_scan_results.json
    expire_in: 1 week
```

## Najlepsze praktyki

1. **Regularne skanowanie**: Włącz automatyczne skanowanie w pipeline CI/CD
2. **Monitoring wyników**: Ustaw alerty dla problemów wysokiej/krytycznej ważności
3. **Aktualizacje**: Regularnie aktualizuj bazy danych luk (Trivy robi to automatycznie)
4. **Filtrowanie**: Dostosuj wykluczenia według potrzeb projektu
5. **Dokumentacja**: Dokumentuj znane false-positive i uzasadnienia dla ignorowanych problemów

## Rozwiązywanie problemów

### Częste problemy

1. **Trivy nie znalezione**: Upewnij się, że trivy jest zainstalowane i dostępne w PATH (`which trivy`)
2. **Błędy połączenia Trivy**: Sprawdź połączenie internetowe (pobieranie baz danych luk)
3. **Błędy skanowania obrazów**: Upewnij się, że Docker daemon jest uruchomiony (potrzebny do pobierania obrazów)
4. **Błędy Bandit**: Sprawdź czy projekt zawiera kod Python
5. **Brak obrazów**: Sprawdź czy pliki docker-compose zawierają poprawne definicje obrazów

### Debugowanie

```bash
# Sprawdź czy trivy jest dostępne
trivy --version

# Test połączenia i baz danych
trivy image --help

# Włącz szczegółowe logowanie
export PYTHONPATH=/path/to/project
python -c "
import logging
logging.basicConfig(level=logging.DEBUG)
from deployment_scanner.aggregate import aggregate_scan
aggregate_scan('.')
"
```

## Rozwój

### Dodawanie nowych skanerów

1. Stwórz nowy handler w `handlers/`
2. Dodaj import w `aggregate.py`
3. Dodaj wywołanie w funkcji `aggregate_scan()`
4. Zaktualizuj funkcję `_generate_summary()`

### Testowanie

```bash
# Uruchom testy jednostkowe
python -m pytest tests/test_aggregate.py

# Test na przykładowym projekcie
python backend/example_usage.py
```
