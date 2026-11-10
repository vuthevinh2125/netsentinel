"""A small offline slice of MITRE ATT&CK for the techniques NetSentinel detects."""

ATTACK = {
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "summary": "The adversary probes hosts for open ports and running services to choose next targets.",
        "detection": "Many destination ports or hosts from one source in a short time, mostly unanswered.",
        "response": ["Confirm whether the source is an authorised scanner", "Isolate the source if it is a user workstation",
                     "Review which services answered and patch or firewall them"],
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "summary": "Repeated login attempts to guess passwords; a success after many failures means the account is likely compromised.",
        "detection": "Bursts of failed logins against one service, especially from the internet, followed by a success.",
        "response": ["Disable or reset the account that logged in", "Block the source IP at the edge",
                     "Require keys or MFA for SSH and remove password login", "Review commands run in the session"],
    },
    "T1021.002": {
        "name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "summary": "Valid (often stolen) credentials are used over SMB to reach other machines' admin shares.",
        "detection": "One account touching many hosts over 445 in minutes, from a host it does not normally use.",
        "response": ["Reset the account's credentials and revoke sessions", "Check the reached hosts for new services or scheduled tasks",
                     "Restrict admin accounts to admin workstations (tiering)"],
    },
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "summary": "Malware calls home over HTTP(S) at a regular rhythm to receive commands.",
        "detection": "Small, evenly spaced connections from one host to a rare external destination.",
        "response": ["Block the destination at the proxy and firewall", "Isolate the host and collect memory and disk",
                     "Hunt for the same destination across all hosts"],
    },
    "T1071.004": {
        "name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
        "summary": "Data or commands are hidden in DNS queries, usually long random subdomains of one domain.",
        "detection": "Many unique, long, high-entropy subdomains of a single rare domain, often TXT records.",
        "response": ["Sinkhole or block the domain at the resolver", "Isolate the host",
                     "Force clients to use internal resolvers only"],
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "summary": "Large volumes of data are sent out to an attacker-controlled host.",
        "detection": "Unusually large outbound transfer, at an odd hour, to a destination never seen before.",
        "response": ["Block the destination", "Identify what data left and start breach notification steps",
                     "Rotate credentials stored on the source server"],
    },
}


def lookup(technique_id: str) -> dict:
    t = ATTACK.get(technique_id)
    if t is None:
        return {"technique_id": technique_id, "error": "Not in the local ATT&CK table."}
    return {"technique_id": technique_id, **t, "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"}
