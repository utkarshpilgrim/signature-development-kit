# CDAC: Vulnerability Signature Development Kit

## Overview

This repository is the central development and testing kit for the Vulnerability Intelligence team at Sentinel Forge. It contains the source code for all detection signatures, the automated testing harness, reproducible lab environments, and research notes that power our flagship vulnerability scanner. The purpose of this kit is to provide a structured, collaborative, and high-quality environment for translating vulnerability research into robust, production-grade detection logic that protects thousands of our customers.

## Developer Workflow Overview

Our development process follows a rigorous, research-driven lifecycle. This ensures that every signature is accurate, performant, and has a low false-positive rate before being deployed to customers.

`[CVE Analysis] -> [Lab Environment Setup] -> [Signature Development (Lua/Python)] -> [Automated Testing & PCAP Analysis] -> [Peer Review] -> [Deployment]`

*   **CVE Analysis:** Research is conducted and documented in the `/research` directory.
*   **Lab Setup:** Vulnerable environments are defined in `/lab-environments` using Docker for rapid, reproducible testing.
*   **Signature Development:** Detection logic is written in Lua (for network performance) or Python (for complex application logic) and stored in `/signatures`.
*   **Automated Testing:** A Python-based test harness (`/test-harness`) validates signature accuracy against the lab environments.

## Technology Stack

*   **Signature Languages:** Lua 5.3, Python 3.9+
*   **Lab Environment:** Docker, Docker Compose
*   **Automation & Testing:** Python (pytest, requests), Bash
*   **Core Skills:** Network Protocol Analysis (TCP/IP, HTTP/SSL), Regular Expressions (PCRE), Packet Analysis (Wireshark)
*   **Version Control:** Git

## Key Features

*   **Modular Signature Architecture:** Signatures are organized by language and protocol, making them easy to maintain and test.
*   **Reproducible Test Labs:** Dockerized environments ensure consistent testing results for specific vulnerabilities (e.g., Log4Shell, Apache Struts).
*   **Automated Test Harness:** A Python framework for orchestrating tests, running signatures against targets, and asserting detection outcomes.
*   **Centralized CVE Research:** A dedicated directory for storing vulnerability analysis, PoC code, and reference PCAPs.
*   **CI/CD Validation Hooks:** Includes tooling for static analysis, such as validating regex complexity to prevent scanner performance degradation.

## Getting Started

### Prerequisites

*   Python 3.9+
*   Docker & Docker Compose
*   Wireshark (for manual analysis)

### Running a Test Signature

1.  **Set up a vulnerable environment:** Navigate to a lab environment and start it.
    ```bash
    cd lab-environments/cve-2021-44228-log4shell
    docker-compose up -d
    ```

2.  **Run the test harness:** Execute the main test runner, pointing it to the signature you want to test and the target environment definition.
    ```bash
    # (From the project root)
    python test-harness/run_test.py --signature signatures/lua/http/log4shell_rce.lua --target lab-environments/cve-2021-44228-log4shell/target.yaml
    ```
