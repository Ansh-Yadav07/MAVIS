"""Analyst knowledge attached to every MAVIS verdict: what the attack is, where it sits in
MITRE ATT&CK, how much damage it can do, and what to do about it.

`impact` (0..1) is the business impact if the detection is real. The engine combines it with
the likelihood from the models: risk = likelihood x impact weight.
"""

NOVEL = 'Novel'

THREATS = {
    'DoS': {
        'title': 'Denial of Service',
        'description': 'One host floods a service (HTTP floods, Slowloris, slow-POST) to exhaust it.',
        'mitre': [('TA0040 Impact', 'T1499 Endpoint Denial of Service')],
        'impact': 0.6,
        'actions': [
            'Rate-limit or temporarily block the source at the edge firewall / load balancer.',
            'Check the target service for exhausted worker pools or connection tables.',
            'Enable slow-request timeouts (e.g. reverse-proxy header/body timeouts).',
        ],
    },
    'DDoS': {
        'title': 'Distributed Denial of Service',
        'description': 'Many sources flood a target at once, saturating bandwidth or the service.',
        'mitre': [('TA0040 Impact', 'T1498 Network Denial of Service')],
        'impact': 0.7,
        'actions': [
            'Engage upstream DDoS scrubbing / CDN protection for the targeted address.',
            'Apply geo or ASN rate limits; block the top offending source ranges.',
            'Watch service health and bandwidth on the targeted link.',
        ],
    },
    'PortScan': {
        'title': 'Port Scan / Reconnaissance',
        'description': 'A host probes many ports to map running services, usually before an attack.',
        'mitre': [('TA0043 Reconnaissance', 'T1595 Active Scanning'),
                  ('TA0007 Discovery', 'T1046 Network Service Discovery')],
        'impact': 0.4,
        'actions': [
            'Block or tarpit the scanning source; check whether it is an internal host.',
            'Review which ports answered and close services that should not be exposed.',
            'Raise monitoring on the scanned hosts: an attack often follows a scan.',
        ],
    },
    'BruteForce': {
        'title': 'Credential Brute Force',
        'description': 'Repeated login attempts against FTP/SSH or similar services.',
        'mitre': [('TA0006 Credential Access', 'T1110 Brute Force')],
        'impact': 0.75,
        'actions': [
            'Lock or throttle the targeted accounts; block the source IP.',
            'Check authentication logs for any successful login from the source.',
            'Enforce MFA and key-based SSH; disable password login where possible.',
        ],
    },
    'WebAttack': {
        'title': 'Web Application Attack',
        'description': 'SQL injection, XSS or login brute force against a web application.',
        'mitre': [('TA0001 Initial Access', 'T1190 Exploit Public-Facing Application')],
        'impact': 0.8,
        'actions': [
            'Inspect the web server / WAF logs for the payloads sent by the source.',
            'Block the source and enable WAF rules for SQLi / XSS.',
            'Check the application database for unexpected changes or data access.',
        ],
    },
    'Bot': {
        'title': 'Botnet / Command and Control',
        'description': 'An infected host beacons to a controller for commands (e.g. Ares botnet).',
        'mitre': [('TA0011 Command and Control', 'T1071 Application Layer Protocol')],
        'impact': 0.9,
        'actions': [
            'Isolate the internal host: it is likely already compromised.',
            'Block the controller address/domain at the firewall and DNS.',
            'Run endpoint forensics on the host and look for the same beacon elsewhere.',
        ],
    },
    'Infiltration': {
        'title': 'Network Infiltration',
        'description': 'A host inside the network, compromised via a malicious file, attacks or scans from within.',
        'mitre': [('TA0002 Execution', 'T1204 User Execution'),
                  ('TA0008 Lateral Movement', 'T1021 Remote Services')],
        'impact': 1.0,
        'actions': [
            'Isolate the internal host immediately and preserve it for forensics.',
            'Find how the payload arrived (email, download) and block that path.',
            'Hunt for the same behaviour on other hosts; reset credentials used on the host.',
        ],
    },
    'Heartbleed': {
        'title': 'Heartbleed (CVE-2014-0160)',
        'description': 'Malformed TLS heartbeats leak server memory, including keys and passwords.',
        'mitre': [('TA0001 Initial Access', 'T1190 Exploit Public-Facing Application')],
        'impact': 1.0,
        'actions': [
            'Patch OpenSSL on the target immediately.',
            'Revoke and reissue TLS certificates/keys; force password resets.',
            'Assume memory contents leaked: review what the server held.',
        ],
    },
    NOVEL: {
        'title': 'Unknown anomalous behaviour',
        'description': ('Traffic that the anomaly models find highly unusual but that does not match any '
                        'known attack family. Could be a new (zero-day) attack, a misconfiguration or rare '
                        'legitimate traffic.'),
        'mitre': [],
        'impact': 0.7,
        'actions': [
            'Review the top deviating features listed in the explanation.',
            'Check whether the source/destination is expected to talk this way.',
            'If benign, mark it as a false positive so it can be learned as normal.',
        ],
    },
}

SEVERITY_BANDS = [('Critical', 85), ('High', 70), ('Medium', 50), ('Low', 0)]


def severity_for(risk, alert_threshold):
    """Severity label for a risk score (0-100); below the calibrated alert threshold it is 'None'."""
    if risk < alert_threshold:
        return 'None'
    for name, floor in SEVERITY_BANDS:
        if risk >= floor:
            return name
    return 'Low'
