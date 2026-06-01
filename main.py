import re

class SolidityContractScanner:
    """
    Solidity Smart Contract Security Scanner
    Uses regular expression-based static analysis to identify typical blockchain vulnerabilities.
    """
    def __init__(self):
        self.rules = {
            "reentrancy": {
                "pattern": r"\.call\{value:.*\}\(.*?\);",
                "severity": "HIGH",
                "message": "Potential reentrancy vulnerability. External call occurs before state update."
            },
            "unprotected_selfdestruct": {
                "pattern": r"selfdestruct\(.*?\);",
                "severity": "CRITICAL",
                "message": "Unprotected selfdestruct function. Ensure proper access controls are active."
            }
        }

    def scan(self, code_content):
        findings = []
        lines = code_content.split("\n")
        for i, line in enumerate(lines, 1):
            for vuln, rule in self.rules.items():
                if re.search(rule["pattern"], line):
                    findings.append({
                        "line": i,
                        "vulnerability": vuln,
                        "severity": rule["severity"],
                        "message": rule["message"]
                    })
        return findings

if __name__ == "__main__":
    mock_contract = """
    contract Dangerous {
        mapping(address => uint) balances;
        function withdraw() public {
            msg.sender.call{value: balances[msg.sender]}("");
            balances[msg.sender] = 0;
        }
    }
    """
    scanner = SolidityContractScanner()
    print("Solidity Security Scan Report:")
    for finding in scanner.scan(mock_contract):
        print(f"Line {finding['line']}: [{finding['severity']}] {finding['message']}")
