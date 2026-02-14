"""Tool definitions for the AI agent — maps to security scanners."""

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "run_subdomain_scan",
            "description": "Enumerate subdomains of a target domain using passive sources (Subfinder). Use this for reconnaissance to discover the target's attack surface.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "The target domain to enumerate subdomains for (e.g., 'example.com')"
                    }
                },
                "required": ["domain"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_port_scan",
            "description": "Scan a target for open ports and identify running services using Nmap. Use this to discover what services are exposed.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The target IP or hostname to scan"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port specification (e.g., '80,443,8080' or '1-1000'). Leave empty for default ports."
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["quick", "service", "full"],
                        "description": "Scan intensity: 'quick' (top ports), 'service' (version detection), 'full' (comprehensive with scripts)"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_nuclei_scan",
            "description": "Run Nuclei vulnerability scanner with community templates against a target. Detects known CVEs, misconfigurations, and security issues.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The target URL to scan (e.g., 'https://example.com')"
                    },
                    "severity": {
                        "type": "string",
                        "description": "Filter templates by severity (e.g., 'critical,high' or 'medium,low')"
                    },
                    "tags": {
                        "type": "string",
                        "description": "Filter templates by tags (e.g., 'cve,owasp' or 'tech-detect')"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_api_scan",
            "description": "Test a target for API security issues including missing security headers, CORS misconfiguration, exposed endpoints, and dangerous HTTP methods.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The base URL of the API to test (e.g., 'https://api.example.com')"
                    },
                    "endpoints": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Specific API endpoints to test (e.g., ['/api/users', '/api/auth']). Leave empty to test common paths."
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_owasp_check",
            "description": "Check a target for OWASP Top 10 misconfigurations including insecure cookies, missing HTTPS, verbose errors, and rate limiting issues.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The URL to check (e.g., 'https://example.com')"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_httpx_probe",
            "description": "Probe hosts/URLs to check if they're alive, detect technologies, web servers, status codes, and page titles using httpx. Useful after subdomain enumeration to identify live targets.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The target URL or domain to probe (e.g., 'https://example.com')"
                    },
                    "targets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Multiple targets to probe at once (e.g., list of subdomains from subfinder)"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_tls_scan",
            "description": "Deep TLS/SSL analysis using testssl.sh — checks cipher suites, protocols, certificate chain, and known vulnerabilities (BEAST, POODLE, Heartbleed, SWEET32, etc.).",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The target host to analyze TLS on (e.g., 'https://example.com' or 'example.com')"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_directory_fuzz",
            "description": "Brute-force directories and files on a web server using ffuf with a wordlist. Discovers hidden admin panels, backup files, configuration files, and exposed sensitive paths.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The base URL to fuzz (e.g., 'https://example.com')"
                    },
                    "wordlist": {
                        "type": "string",
                        "enum": ["/usr/share/wordlists/common.txt", "/usr/share/wordlists/raft-small-directories.txt"],
                        "description": "Wordlist to use for fuzzing. 'common.txt' (4600 entries, fast) or 'raft-small-directories.txt' (20000 entries, thorough)"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_crawl",
            "description": "Crawl a website to discover all endpoints, JavaScript files, API routes, forms, and hidden parameters using katana. Feeds discovered URLs into further scanning.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The target URL to crawl (e.g., 'https://example.com')"
                    },
                    "depth": {
                        "type": "string",
                        "description": "Crawl depth (default: 3). Higher values discover more but take longer."
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_dns_scan",
            "description": "DNS enumeration and analysis using dnsx — discovers A, AAAA, MX, NS, TXT, CNAME, SOA records. Checks for SPF/DMARC/DKIM email security, dangling CNAME records (subdomain takeover), and DNS misconfigurations.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The target domain for DNS analysis (e.g., 'example.com')"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_nikto_scan",
            "description": "Classic web server vulnerability scanner using Nikto. Finds outdated software, dangerous files/CGIs, server misconfigurations, and default installations. Complements Nuclei with different detection techniques.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "The target URL to scan (e.g., 'https://example.com')"
                    }
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "generate_report",
            "description": "Generate a comprehensive penetration test report summarizing all findings from the current session.",
            "parameters": {
                "type": "object",
                "properties": {
                    "format": {
                        "type": "string",
                        "enum": ["markdown", "json"],
                        "description": "Report format (default: markdown)"
                    }
                },
                "required": []
            }
        }
    },
]
