from pydantic import BaseModel, Field, validator
from typing import Optional, List
from enum import Enum
import re

class ScanType(str, Enum):
    """Types de scan disponibles"""
    PASSIVE = "passive"
    ACTIVE = "active"
    COMPREHENSIVE = "comprehensive"

class Priority(str, Enum):
    """Priorité du scan"""
    LOW = "low"
    NORMAL = "normal" 
    HIGH = "high"

def detect_target_type(req: str):
        input_str = req

        patterns = {
            "ip_address": r"^(?:\d{1,3}\.){3}\d{1,3}$",
            "cidr": r"^(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}$",
            "domain": r"^(?!http)(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$",
            "subdomain": r"^(?!http)(?:[a-zA-Z0-9-]+\.){2,}[a-zA-Z]{2,}$",
            "email": r"^[\w\.-]+@[\w\.-]+\.\w+$",
            "phone_number": r"^\+?\d{7,15}$",
            "asn": r"^AS\d+$",
            "bitcoin_address": r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$",
            "username": r"^@?[a-zA-Z0-9_]{3,30}$",
            "person_name": r"^[A-Z][a-z]+(?:\s[A-Z][a-z]+)+$",
            "hostname": r"^(?!http)(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
        }

        for target_type, pattern in patterns.items():
            if re.match(pattern, input_str):
                return {"target_type": target_type, "input": input_str}

        return {"target_type": "unknown", "input": input_str}
class ScanRequest(BaseModel):
    # Paramètres de base
    scan_name: str = Field(..., description="Nom du scan", min_length=1, max_length=100)
    target: str = Field(..., description="Cible du scan (domaine, IP, etc.)")
    #typelist : str = Field(
    #    default="type_ACCOUNT_EXTERNAL_OWNED,type_AFFILIATE_COMPANY_NAME,type_AFFILIATE_DOMAIN_NAME,type_AFFILIATE_DOMAIN_UNREGISTERED,type_AFFILIATE_DOMAIN_WHOIS,type_AFFILIATE_EMAILADDR,type_AFFILIATE_IPADDR,type_AFFILIATE_IPV6_ADDRESS,type_AFFILIATE_INTERNET_NAME,type_AFFILIATE_INTERNET_NAME_UNRESOLVED,type_AFFILIATE_INTERNET_NAME_HIJACKABLE,type_AFFILIATE_WEB_CONTENT,type_AFFILIATE_DESCRIPTION_ABSTRACT,type_AFFILIATE_DESCRIPTION_CATEGORY,type_APPSTORE_ENTRY,type_BGP_AS_MEMBER,type_BGP_AS_OWNER,type_BASE64_DATA,type_BITCOIN_ADDRESS,type_BITCOIN_BALANCE,type_BLACKLISTED_AFFILIATE_IPADDR,type_BLACKLISTED_AFFILIATE_INTERNET_NAME,type_BLACKLISTED_COHOST,type_BLACKLISTED_IPADDR,type_BLACKLISTED_NETBLOCK,type_BLACKLISTED_SUBNET,type_BLACKLISTED_INTERNET_NAME,type_CLOUD_STORAGE_BUCKET,type_CLOUD_STORAGE_BUCKET_OPEN,type_CO_HOSTED_SITE,type_CO_HOSTED_SITE_DOMAIN,type_CO_HOSTED_SITE_DOMAIN_WHOIS,type_COMPANY_NAME,type_PASSWORD_COMPROMISED,type_HASH_COMPROMISED,type_TARGET_WEB_COOKIE,type_COUNTRY_NAME,type_CREDIT_CARD_NUMBER,type_DNS_SPF,type_DNS_SRV,type_DNS_TEXT,type_DARKNET_MENTION_URL,type_DARKNET_MENTION_CONTENT,type_DATE_HUMAN_DOB,type_DEFACED_INTERNET_NAME,type_DEFACED_AFFILIATE_INTERNET_NAME,type_DEFACED_AFFILIATE_IPADDR,type_DEFACED_COHOST,type_DEFACED_IPADDR,type_EMAILADDR_DELIVERABLE,type_DESCRIPTION_ABSTRACT,type_DESCRIPTION_CATEGORY,type_DEVICE_TYPE,type_EMAILADDR_DISPOSABLE,type_DOMAIN_NAME,type_DOMAIN_NAME_PARENT,type_DOMAIN_REGISTRAR,type_DOMAIN_WHOIS,type_EMAILADDR,type_EMAILADDR_GENERIC,type_PROVIDER_MAIL,type_ERROR_MESSAGE,type_ETHEREUM_ADDRESS,type_ETHEREUM_BALANCE,type_PROVIDER_JAVASCRIPT,type_WEBSERVER_HTTPHEADERS,type_HTTP_CODE,type_ACCOUNT_EXTERNAL_OWNED_COMPROMISED,type_EMAILADDR_COMPROMISED,type_ACCOUNT_EXTERNAL_USER_SHARED_COMPROMISED,type_HASH,type_INTERESTING_FILE_HISTORIC,type_URL_PASSWORD_HISTORIC,type_URL_UPLOAD_HISTORIC,type_URL_FORM_HISTORIC,type_URL_STATIC_HISTORIC,type_URL_FLASH_HISTORIC,type_URL_JAVA_APPLET_HISTORIC,type_URL_JAVASCRIPT_HISTORIC,type_URL_WEB_FRAMEWORK_HISTORIC,type_PROVIDER_HOSTING,type_HUMAN_NAME,type_IBAN_NUMBER,type_IP_ADDRESS,type_INTERNAL_IP_ADDRESS,type_IPV6_ADDRESS,type_INTERESTING_FILE,type_ROOT,type_INTERNET_NAME,type_INTERNET_NAME_UNRESOLVED,type_JOB_TITLE,type_JUNK_FILE,type_LEAKSITE_CONTENT,type_LEAKSITE_URL,type_LEI,type_LINKED_URL_EXTERNAL,type_LINKED_URL_INTERNAL,type_MALICIOUS_ASN,type_MALICIOUS_AFFILIATE_INTERNET_NAME,type_MALICIOUS_AFFILIATE_IPADDR,type_MALICIOUS_BITCOIN_ADDRESS,type_MALICIOUS_COHOST,type_MALICIOUS_EMAILADDR,type_MALICIOUS_IPADDR,type_MALICIOUS_NETBLOCK,type_MALICIOUS_SUBNET,type_MALICIOUS_INTERNET_NAME,type_MALICIOUS_PHONE_NUMBER,type_PROVIDER_DNS,type_NETBLOCKV6_MEMBER,type_NETBLOCKV6_OWNER,type_NETBLOCK_MEMBER,type_NETBLOCK_OWNER,type_NETBLOCK_WHOIS,type_WEBSERVER_STRANGEHEADER,type_TCP_PORT_OPEN,type_TCP_PORT_OPEN_BANNER,type_UDP_PORT_OPEN,type_UDP_PORT_OPEN_INFO,type_OPERATING_SYSTEM,type_PGP_KEY,type_PHONE_NUMBER,type_PHONE_NUMBER_COMPROMISED,type_PHONE_NUMBER_TYPE,type_PHYSICAL_ADDRESS,type_PHYSICAL_COORDINATES,type_GEOINFO,type_PROXY_HOST,type_PUBLIC_CODE_REPO,type_RAW_DNS_RECORDS,type_RAW_RIR_DATA,type_RAW_FILE_META_DATA,type_SSL_CERTIFICATE_ISSUER,type_SSL_CERTIFICATE_ISSUED,type_SSL_CERTIFICATE_RAW,type_SSL_CERTIFICATE_EXPIRED,type_SSL_CERTIFICATE_EXPIRING,type_SSL_CERTIFICATE_MISMATCH,type_SEARCH_ENGINE_WEB_CONTENT,type_SIMILAR_ACCOUNT_EXTERNAL,type_SIMILARDOMAIN,type_SIMILARDOMAIN_WHOIS,type_SOCIAL_MEDIA,type_SOFTWARE_USED,type_TOR_EXIT_NODE,type_PROVIDER_TELCO,type_URL_PASSWORD,type_URL_UPLOAD,type_URL_ADBLOCKED_EXTERNAL,type_URL_ADBLOCKED_INTERNAL,type_URL_FORM,type_URL_STATIC,type_URL_FLASH,type_URL_JAVA_APPLET,type_URL_JAVASCRIPT,type_URL_WEB_FRAMEWORK,type_EMAILADDR_UNDELIVERABLE,type_USERNAME,type_VPN_HOST,type_VULNERABILITY_CVE_CRITICAL,type_VULNERABILITY_CVE_HIGH,type_VULNERABILITY_CVE_LOW,type_VULNERABILITY_CVE_MEDIUM,type_VULNERABILITY_GENERAL,type_VULNERABILITY_DISCLOSURE,type_WEB_ANALYTICS_ID,type_TARGET_WEB_CONTENT,type_TARGET_WEB_CONTENT_TYPE,type_WEBSERVER_BANNER,type_WEBSERVER_TECHNOLOGY,type_WIFI_ACCESS_POINT,type_WIKIPEDIA_PAGE_EDIT,",
    #    description="Types SpiderFoot séparés par des virgules"
    #)
    use_case: str = Field(
        default = "all" ,
        description="Cible du scan (domaine, IP, etc.)")
    
    # Modules SpiderFoot
    modules: str = Field(
        default="",
        description="Modules SpiderFoot séparés par des virgules. Par exemple : sfp_dnsresolve,sfp_whois,sfp_subdomain_enum,sfp_port_scan_tcp"
    )
    
    # Configuration du scan
    #scan_type: ScanType = Field(default=ScanType.PASSIVE, description="Type de scan")
    #priority: Priority = Field(default=Priority.NORMAL, description="Priorité du scan")
    
    # Paramètres temporels
    #max_scan_time: Optional[int] = Field(
    #    default=3600, 
    #    description="Durée maximale du scan en secondes",
    #    ge=60,
    #    le=86400
    #)
    
    # Paramètres de profondeur
    #max_depth: Optional[int] = Field(
    #    default=3,
    #    description="Profondeur maximale de récursion",
    #    ge=1,
    #    le=10
    #)
    
    # Filtres et exclusions
    #excluded_modules: Optional[str] = Field(
    #    default=None,
    #    description="Modules à exclure, séparés par des virgules"
    #)
    
    #excluded_domains: Optional[List[str]] = Field(
    #    default=None,
    #    description="Domaines à exclure du scan"
    #)
    
    # Paramètres réseau
    #delay_between_requests: Optional[float] = Field(
    #    default=0.5,
    #    description="Délai entre les requêtes en secondes",
    #    ge=0.0,
    #    le=10.0
    #)
    
    #max_threads: Optional[int] = Field(
    #    default=10,
    #    description="Nombre maximum de threads",
    #    ge=1,
    #    le=50
    #)
    
    
    
    @validator('use_case')
    def validate_modules(cls, v):
        """Validation de use_case """
        use_case_keys = USE_CASE.keys()
        if not v in use_case_keys:
            raise ValueError(f"use_case must be in [{use_case_keys}]")
        return v.lower()
    
    @validator('target')
    def validate_target(cls, v):
        """Validation basique de la cible"""
        v_strip = v.strip()
        if not v or len(v_strip) < 3:
            raise ValueError("La cible doit contenir au moins 3 caractères")
        #v_strip_type = "+".join(v_strip.split())
        type_detect = detect_target_type(v_strip)
        print("type_detect //// ", type_detect)
        if type_detect['target_type'] in ['person_name','username']:
            v_strip = f'"{v_strip}"'
            print(f"v_stript  {v_strip}")
        print(f"v_strip  {v_strip}")
        return v_strip
    
    

# Modules SpiderFoot populaires organisés par catégorie
SPIDERFOOT_MODULES = {
    "dns_recon": [
        "sfp_dnsresolve",
        "sfp_dnsbrute", 
        "sfp_dnstxt",
        "sfp_subdomain_enum"
    ],
    "whois_info": [
        "sfp_whois",
        "sfp_registrar_info",
        "sfp_domain_history"
    ],
    "port_scanning": [
        "sfp_port_scan_tcp",
        "sfp_port_scan_udp",
        "sfp_banner_grab"
    ],
    "web_recon": [
        "sfp_web_analysis",
        "sfp_robots_txt",
        "sfp_ssl_analysis",
        "sfp_http_headers"
    ],
    "threat_intel": [
        "sfp_virustotal",
        "sfp_shodan",
        "sfp_malware_check",
        "sfp_reputation_check"
    ],
    "social_osint": [
        "sfp_social_networks",
        "sfp_email_enum",
        "sfp_phone_enum"
    ],
    "passive_recon": [
        "sfp_certificate_transparency",
        "sfp_wayback_machine",
        "sfp_google_search",
        "sfp_bing_search"
    ]
}


USE_CASE = {
    "all": "",
    "footprint": "",
    "investigate": "",
    "passive": ""
}


TARGET_MODULES = {
    "ip_address": [
        "sfp_ipinfo", "sfp_shodan", "sfp_censys", "sfp_virustotal",
        "sfp_abuseipdb", "sfp_riskiq"
    ],
    "cidr": [
        "sfp_ipinfo", "sfp_riskiq", "sfp_censys"
    ],
    "domain": [
        "sfp_dnsresolve", "sfp_sublist3r", "sfp_crt", "sfp_whois",
        "sfp_spider", "sfp_dnsdumpster", "sfp_alienvault", "sfp_virustotal"
    ],
    "subdomain": [
        "sfp_dnsresolve", "sfp_crt", "sfp_shodan", "sfp_censys", "sfp_riskiq"
    ],
    "hostname": [
        "sfp_dnsresolve", "sfp_shodan", "sfp_censys", "sfp_riskiq"
    ],
    "asn": [
        "sfp_ipinfo", "sfp_riskiq", "sfp_censys"
    ],
    "email": [
        "sfp_email", "sfp_hunter", "sfp_pwned", "sfp_fullcontact", "sfp_botscout"
    ],
    "phone_number": [
        "sfp_phone", "sfp_fullcontact"
    ],
    "username": [
        "sfp_username", "sfp_fullcontact", "sfp_pwned", "sfp_twitter", "sfp_facebook"
    ],
    "person_name": [
        "sfp_fullcontact", "sfp_clearbit", "sfp_pipl"
    ],
    "bitcoin_address": [
        "sfp_bitcoinabuse", "sfp_walletexplorer"
    ]
}


TYPE_CATEGORIES = {
    "ip_address": [
        "type_IP_ADDRESS", "type_INTERNAL_IP_ADDRESS", "type_IPV6_ADDRESS",
        "type_BLACKLISTED_IPADDR", "type_MALICIOUS_IPADDR"
    ],
    "domain": [
        "type_DOMAIN_NAME", "type_DOMAIN_WHOIS", "type_DOMAIN_REGISTRAR",
        "type_SIMILARDOMAIN", "type_AFFILIATE_DOMAIN_NAME"
    ],
    "subdomain": [
        "type_INTERNET_NAME", "type_INTERNET_NAME_UNRESOLVED",
        "type_AFFILIATE_INTERNET_NAME", "type_DEFACED_INTERNET_NAME"
    ],
    "email": [
        "type_EMAILADDR", "type_EMAILADDR_GENERIC", "type_EMAILADDR_DISPOSABLE",
        "type_EMAILADDR_COMPROMISED", "type_EMAILADDR_UNDELIVERABLE"
    ],
    "phone_number": [
        "type_PHONE_NUMBER", "type_PHONE_NUMBER_COMPROMISED", "type_MALICIOUS_PHONE_NUMBER"
    ],
    "username": [
        "type_USERNAME", "type_SIMILAR_ACCOUNT_EXTERNAL"
    ],
    "person_name": [
        "type_HUMAN_NAME"
    ],
    "bitcoin_address": [
        "type_BITCOIN_ADDRESS", "type_BITCOIN_BALANCE", "type_MALICIOUS_BITCOIN_ADDRESS"
    ],
    "asn": [
        "type_BGP_AS_OWNER", "type_BGP_AS_MEMBER", "type_MALICIOUS_ASN"
    ],
    "cidr": [
        "type_NETBLOCK_OWNER", "type_NETBLOCK_MEMBER", "type_NETBLOCK_WHOIS",
        "type_MALICIOUS_NETBLOCK", "type_BLACKLISTED_NETBLOCK"
    ]
}

TYPESLIST = "type_ACCOUNT_EXTERNAL_OWNED,type_AFFILIATE_COMPANY_NAME,type_AFFILIATE_DOMAIN_NAME,type_AFFILIATE_DOMAIN_UNREGISTERED,type_AFFILIATE_DOMAIN_WHOIS,type_AFFILIATE_EMAILADDR,type_AFFILIATE_IPADDR,type_AFFILIATE_IPV6_ADDRESS,type_AFFILIATE_INTERNET_NAME,type_AFFILIATE_INTERNET_NAME_UNRESOLVED,type_AFFILIATE_INTERNET_NAME_HIJACKABLE,type_AFFILIATE_WEB_CONTENT,type_AFFILIATE_DESCRIPTION_ABSTRACT,type_AFFILIATE_DESCRIPTION_CATEGORY,type_APPSTORE_ENTRY,type_BGP_AS_MEMBER,type_BGP_AS_OWNER,type_BASE64_DATA,type_BITCOIN_ADDRESS,type_BITCOIN_BALANCE,type_BLACKLISTED_AFFILIATE_IPADDR,type_BLACKLISTED_AFFILIATE_INTERNET_NAME,type_BLACKLISTED_COHOST,type_BLACKLISTED_IPADDR,type_BLACKLISTED_NETBLOCK,type_BLACKLISTED_SUBNET,type_BLACKLISTED_INTERNET_NAME,type_CLOUD_STORAGE_BUCKET,type_CLOUD_STORAGE_BUCKET_OPEN,type_CO_HOSTED_SITE,type_CO_HOSTED_SITE_DOMAIN,type_CO_HOSTED_SITE_DOMAIN_WHOIS,type_COMPANY_NAME,type_PASSWORD_COMPROMISED,type_HASH_COMPROMISED,type_TARGET_WEB_COOKIE,type_COUNTRY_NAME,type_CREDIT_CARD_NUMBER,type_DNS_SPF,type_DNS_SRV,type_DNS_TEXT,type_DARKNET_MENTION_URL,type_DARKNET_MENTION_CONTENT,type_DATE_HUMAN_DOB,type_DEFACED_INTERNET_NAME,type_DEFACED_AFFILIATE_INTERNET_NAME,type_DEFACED_AFFILIATE_IPADDR,type_DEFACED_COHOST,type_DEFACED_IPADDR,type_EMAILADDR_DELIVERABLE,type_DESCRIPTION_ABSTRACT,type_DESCRIPTION_CATEGORY,type_DEVICE_TYPE,type_EMAILADDR_DISPOSABLE,type_DOMAIN_NAME,type_DOMAIN_NAME_PARENT,type_DOMAIN_REGISTRAR,type_DOMAIN_WHOIS,type_EMAILADDR,type_EMAILADDR_GENERIC,type_PROVIDER_MAIL,type_ERROR_MESSAGE,type_ETHEREUM_ADDRESS,type_ETHEREUM_BALANCE,type_PROVIDER_JAVASCRIPT,type_WEBSERVER_HTTPHEADERS,type_HTTP_CODE,type_ACCOUNT_EXTERNAL_OWNED_COMPROMISED,type_EMAILADDR_COMPROMISED,type_ACCOUNT_EXTERNAL_USER_SHARED_COMPROMISED,type_HASH,type_INTERESTING_FILE_HISTORIC,type_URL_PASSWORD_HISTORIC,type_URL_UPLOAD_HISTORIC,type_URL_FORM_HISTORIC,type_URL_STATIC_HISTORIC,type_URL_FLASH_HISTORIC,type_URL_JAVA_APPLET_HISTORIC,type_URL_JAVASCRIPT_HISTORIC,type_URL_WEB_FRAMEWORK_HISTORIC,type_PROVIDER_HOSTING,type_HUMAN_NAME,type_IBAN_NUMBER,type_IP_ADDRESS,type_INTERNAL_IP_ADDRESS,type_IPV6_ADDRESS,type_INTERESTING_FILE,type_ROOT,type_INTERNET_NAME,type_INTERNET_NAME_UNRESOLVED,type_JOB_TITLE,type_JUNK_FILE,type_LEAKSITE_CONTENT,type_LEAKSITE_URL,type_LEI,type_LINKED_URL_EXTERNAL,type_LINKED_URL_INTERNAL,type_MALICIOUS_ASN,type_MALICIOUS_AFFILIATE_INTERNET_NAME,type_MALICIOUS_AFFILIATE_IPADDR,type_MALICIOUS_BITCOIN_ADDRESS,type_MALICIOUS_COHOST,type_MALICIOUS_EMAILADDR,type_MALICIOUS_IPADDR,type_MALICIOUS_NETBLOCK,type_MALICIOUS_SUBNET,type_MALICIOUS_INTERNET_NAME,type_MALICIOUS_PHONE_NUMBER,type_PROVIDER_DNS,type_NETBLOCKV6_MEMBER,type_NETBLOCKV6_OWNER,type_NETBLOCK_MEMBER,type_NETBLOCK_OWNER,type_NETBLOCK_WHOIS,type_WEBSERVER_STRANGEHEADER,type_TCP_PORT_OPEN,type_TCP_PORT_OPEN_BANNER,type_UDP_PORT_OPEN,type_UDP_PORT_OPEN_INFO,type_OPERATING_SYSTEM,type_PGP_KEY,type_PHONE_NUMBER,type_PHONE_NUMBER_COMPROMISED,type_PHONE_NUMBER_TYPE,type_PHYSICAL_ADDRESS,type_PHYSICAL_COORDINATES,type_GEOINFO,type_PROXY_HOST,type_PUBLIC_CODE_REPO,type_RAW_DNS_RECORDS,type_RAW_RIR_DATA,type_RAW_FILE_META_DATA,type_SSL_CERTIFICATE_ISSUER,type_SSL_CERTIFICATE_ISSUED,type_SSL_CERTIFICATE_RAW,type_SSL_CERTIFICATE_EXPIRED,type_SSL_CERTIFICATE_EXPIRING,type_SSL_CERTIFICATE_MISMATCH,type_SEARCH_ENGINE_WEB_CONTENT,type_SIMILAR_ACCOUNT_EXTERNAL,type_SIMILARDOMAIN,type_SIMILARDOMAIN_WHOIS,type_SOCIAL_MEDIA,type_SOFTWARE_USED,type_TOR_EXIT_NODE,type_PROVIDER_TELCO,type_URL_PASSWORD,type_URL_UPLOAD,type_URL_ADBLOCKED_EXTERNAL,type_URL_ADBLOCKED_INTERNAL,type_URL_FORM,type_URL_STATIC,type_URL_FLASH,type_URL_JAVA_APPLET,type_URL_JAVASCRIPT,type_URL_WEB_FRAMEWORK,type_EMAILADDR_UNDELIVERABLE,type_USERNAME,type_VPN_HOST,type_VULNERABILITY_CVE_CRITICAL,type_VULNERABILITY_CVE_HIGH,type_VULNERABILITY_CVE_LOW,type_VULNERABILITY_CVE_MEDIUM,type_VULNERABILITY_GENERAL,type_VULNERABILITY_DISCLOSURE,type_WEB_ANALYTICS_ID,type_TARGET_WEB_CONTENT,type_TARGET_WEB_CONTENT_TYPE,type_WEBSERVER_BANNER,type_WEBSERVER_TECHNOLOGY,type_WIFI_ACCESS_POINT,type_WIKIPEDIA_PAGE_EDIT,"