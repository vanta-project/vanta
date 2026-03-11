# Vanta Transport Protocol

## Specs

### General Specifications

- [Protocol Overview](spec/vanta-overview.xml)
- [Core Specification](spec/vanta-core.xml)
- [Handshake and Secure Session Specification](spec/vanta-handshake.xml)
- [Reliability and Control-Plane Specification](spec/vanta-reliability.xml)
- [Audit Chain Specification](spec/vanta-audit.xml)

### Product Requirements & Technical Specification

- [Product Requirements & Technical Specification](spec/PRD.md)

### Generation

When chaing the specifications, re-generate the HTML version of the specifications using the following commands:

```bash
# Make a virtual environment
python -m venv venv
source venv/bin/activate

# Install xml2rfc
pip install -U pip                        
pip install xml2rfc

# Generate the HTML version of the specifications
xml2rfc --text --html spec/vanta-overview.xml
xml2rfc --text --html spec/vanta-core.xml
xml2rfc --text --html spec/vanta-handshake.xml
xml2rfc --text --html spec/vanta-reliability.xml
xml2rfc --text --html spec/vanta-audit.xml
```

## Specification Implementations

> [!IMPORTANT]
> The following implementations marked with `NIP` are not yet available. Work-in-progress implementations are marked with `WIP`.

- [Rust Implementation](https://github.com/vanta-project/vanta-rs) (WIP)
- [Go Implementation](https://github.com/vanta-project/vanta-go) (NIP)
- [TypeScript Implementation](https://github.com/vanta-project/vanta-ts) (NIP)
