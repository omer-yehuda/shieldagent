# ShieldAgent Architecture

## System Overview

```mermaid
graph TD
    User["Developer / CI"]

    subgraph CLI["CLI Layer"]
        Commander["Commander.js CLI<br/>(scan / report)"]
        Zod["Zod v4 Validation"]
    end

    subgraph Config["Configuration"]
        CfgLoader["Config Loader<br/>(.shieldagentrc.json)"]
    end

    subgraph Loader["MCP Loader"]
        FSWalker["FS Walker + Tool Extractor"]
        ScanTarget["ScanTarget"]
    end

    subgraph Engine["Core Engine"]
        ScanEngine["ScanEngine + Registry"]
    end

    subgraph Scanners["Security Scanners (9)"]
        Base["BaseScanner (Abstract)<br/>SHA-256 Fingerprints"]
        S_Schema["Schema:<br/>Input Validation"]
        S_Pattern["Pattern:<br/>Tool Poisoning · Prompt Injection<br/>Auth/Transport · Supply Chain<br/>Secret Detection"]
        S_AST["AST:<br/>Command Injection · Over-Permission<br/>Data Exfiltration"]
    end

    subgraph Output["Reporters"]
        Reporters["Table | JSON | SARIF v2.1.0"]
    end

    subgraph Compliance["Compliance Frameworks"]
        OWASP["OWASP Agentic Top 10"]
        Adversa["Adversa MCP Top 25"]
    end

    User --> Commander
    Commander --> Zod
    Commander --> CfgLoader
    Commander --> FSWalker
    FSWalker --> ScanTarget
    ScanTarget --> ScanEngine
    CfgLoader --> ScanEngine
    ScanEngine --> Base
    Base --> S_Schema
    Base --> S_Pattern
    Base --> S_AST
    ScanEngine --> Reporters
    S_Schema -.-> OWASP
    S_Pattern -.-> OWASP
    S_AST -.-> OWASP
    S_Schema -.-> Adversa
    S_Pattern -.-> Adversa
    S_AST -.-> Adversa

    style CLI fill:#FCE4EC,stroke:#F48FB1,color:#333
    style Config fill:#ECEFF1,stroke:#B0BEC5,color:#333
    style Loader fill:#ECEFF1,stroke:#B0BEC5,color:#333
    style Engine fill:#FFF3E0,stroke:#FFCC80,color:#333
    style Scanners fill:#E0F2F1,stroke:#80CBC4,color:#333
    style Output fill:#E3F2FD,stroke:#90CAF9,color:#333
    style Compliance fill:#FCE4EC,stroke:#F48FB1,color:#333
```

## Scanner Inventory

| # | Scanner | Category | Key Rules |
|---|---------|----------|-----------|
| 1 | Input Validation | schema | IV001–IV006 |
| 2 | Tool Poisoning | pattern | TP001–TP005 |
| 3 | Prompt Injection | pattern | PI001–PI004 |
| 4 | Auth / Transport | pattern | AT001–AT004 |
| 5 | Supply Chain | pattern | SC001–SC005 |
| 6 | Command Injection | ast | CI001–CI005 |
| 7 | Over-Permission | ast | OP001–OP005 |
| 8 | Data Exfiltration | ast | DE001–DE005 |
| 9 | Secret Detection | pattern | SD001–SD004 |

## Compliance Frameworks

### OWASP Agentic Top 10
| ID | Name |
|----|------|
| AT-01 | Tool Poisoning |
| AT-02 | Prompt Injection |
| AT-03 | Command Injection |
| AT-04 | Over-Permission |
| AT-05 | Data Exfiltration |
| AT-06 | Improper Input Validation |
| AT-07 | Missing Authentication |
| AT-08 | Credential Exposure |
| AT-09 | Supply Chain Compromise |
| AT-10 | Insecure Transport |

### Adversa MCP Top 25 (mapped)
| ID | Name |
|----|------|
| MCP-01 | Tool Poisoning Attack |
| MCP-02 | Rug Pull via Tool Modification |
| MCP-03 | Tool Shadowing |
| MCP-04 | Prompt Injection via Tool Description |
| MCP-05 | Command Injection via Tool Input |
| MCP-06 | Data Exfiltration via Tool |
| MCP-07 | Credential Leakage in Tool Definitions |
| MCP-08 | Lack of Authentication |
| MCP-09 | Insecure Transport |
| MCP-10 | Excessive Permissions |
| MCP-14 | Missing Input Validation |
| MCP-20 | Malicious npm Package |
| MCP-21 | Typosquatting Attack |
