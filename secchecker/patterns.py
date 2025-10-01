PATTERNS = {
    "Postgres URI": r"postgres:\/\/[a-zA-Z0-9]+:[^@]+@[^:]+:\d+\/[a-zA-Z0-9_]+",
    "MySQL URI": r"mysql:\/\/[a-zA-Z0-9]+:[^@]+@[^:]+:\d+\/[a-zA-Z0-9_]+",
    "Mongo URI": r"mongodb\+srv:\/\/[a-zA-Z0-9]+:[^@]+@[^\/]+\/[a-zA-Z0-9_-]+",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Azure Client Secret": r"(?i)azure.*(client|secret)[\"'\s:=]+[0-9a-zA-Z\.\-_]+",
    "JWT Token": r"eyJ[a-zA-Z0-9_-]+?\.[a-zA-Z0-9_-]+?\.[a-zA-Z0-9_-]+",
    "Private Key": r"-----BEGIN (RSA|EC|DSA)? ?PRIVATE KEY-----",
    "Password in Config": r"(password|pwd)\s*[:=]\s*['\"].+?['\"]",
    "API Key": r"(?i)api[-]?key['\"\s:=]+[0-9a-zA-Z\.\-]+"
}
