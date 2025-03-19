#!/usr/bin/env python3
"""
Response Analyzer module for the SQL Injection Fuzzer
"""

import re


class ResponseAnalyzer:
    def __init__(self, verbose=False):
        self.verbose = verbose

        # Initialize patterns for common SQL error messages (MySQL specific)
        self._init_patterns()

    def _init_patterns(self):
        """Initialize regex patterns for SQL error detection"""

        # MySQL error patterns
        self.mysql_error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"MySQL Query fail.*",
            r"SQL syntax.*MariaDB server",
            r"Unknown column '[^']+' in 'field list'",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc\.exceptions",
            r"Unclosed quotation mark after the character string",
            r"Syntax error or access violation:",
            r"mysql_fetch_array\(\)",
            r"YOU HAVE AN ERROR IN YOUR SQL SYNTAX",
            r"DATABASE\.MYSQL\.DRIVER",
            r"supplied argument is not a valid MySQL",
            r"javax\.el\.ELException: The identifier \[mysql\]"
        ]

        # Generic database error patterns
        self.generic_error_patterns = [
            r"DB Error",
            r"SQL Error",
            r"SQL syntax.*",
            r"Warning.*SQL.*",
            r"Warning.*syntax.*",
            r"Warning.*for user '.*'",
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Microsoft OLE DB Provider for SQL Server error",
            r"ODBC.*Driver",
            r"Error.*\bODBC\b.*Driver",
            r"Exception.*java\.sql\.SQLException",
            r"Unclosed quotation mark after the character string",
            r"quoted string not properly terminated",
            r"Syntax error.*in query expression",
            r"Data type mismatch"
        ]

        # Union select patterns (for detecting successful UNION-based injections)
        self.union_select_patterns = [
            r"\b\d+\b\s*,\s*\b\d+\b",           # For simple numeric columns like "1, 2, 3"
            r"[0-9]+ rows in set",              # MySQL rows message
            r"appears more than once in the SELECT list",
        ]

        # Authentication bypass patterns
        self.auth_bypass_patterns = [
            r"Welcome.*admin",
            r"Login successful",
            r"Admin.*panel",
            r"Dashboard",
            r"Logout"
        ]

    def analyze(self, response, payload):
        """
        Analyze response to detect potential SQL injection vulnerabilities

        Args:
            response (requests.Response): HTTP response object
            payload (str): The SQL injection payload that was used

        Returns:
            dict: Analysis result containing vulnerability status and details
        """
        result = {
            'vulnerable': False,
            'details': ''
        }

        # Check if response is valid
        if not response or not hasattr(response, 'text'):
            return result

        # Store original response info
        status_code = response.status_code
        response_text = response.text
        content_length = len(response_text)

        # Check for SQL errors in response
        if self._check_sql_errors(response_text):
            result['vulnerable'] = True
            result['details'] = 'SQL error detected in response'
            return result

        # Check for specific UNION SELECT patterns
        if 'UNION SELECT' in payload.upper() and self._check_union_select(response_text):
            result['vulnerable'] = True
            result['details'] = 'UNION SELECT injection likely successful'
            return result

        # Check for authentication bypass patterns in auth-related payloads
        if any(bypass_term in payload.lower() for bypass_term in ['admin', 'login', 'user']) and self._check_auth_bypass(response_text):
            result['vulnerable'] = True
            result['details'] = 'Authentication bypass likely successful'
            return result

        # Check for time-based injections (handled differently, but we'll include placeholder logic)
        if 'SLEEP' in payload.upper() or 'BENCHMARK' in payload.upper() or 'DELAY' in payload.upper():
            # Time-based vulnerabilities are typically detected by measuring response time
            # This would require specialized timing analysis which is beyond our simple analyzer
            # We'll just log these for manual verification
            if self.verbose:
                result['details'] = 'Possible time-based injection (needs manual verification)'

        # Additional analysis could be added here

        return result

    def _check_sql_errors(self, response_text):
        """
        Check for SQL error messages in response

        Args:
            response_text (str): Response body text

        Returns:
            bool: True if SQL errors detected, False otherwise
        """
        # Check MySQL specific errors
        for pattern in self.mysql_error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        # Check generic SQL errors
        for pattern in self.generic_error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        return False

    def _check_union_select(self, response_text):
        """
        Check for successful UNION SELECT injection markers

        Args:
            response_text (str): Response body text

        Returns:
            bool: True if UNION SELECT markers detected, False otherwise
        """
        for pattern in self.union_select_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        return False

    def _check_auth_bypass(self, response_text):
        """
        Check for authentication bypass indicators

        Args:
            response_text (str): Response body text

        Returns:
            bool: True if auth bypass indicators detected, False otherwise
        """
        for pattern in self.auth_bypass_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True

        return False

    def compare_responses(self, baseline_response, test_response):
        """
        Compare two responses to detect differences that might indicate a vulnerability

        Args:
            baseline_response (requests.Response): Baseline response (original request)
            test_response (requests.Response): Test response (with payload)

        Returns:
            dict: Comparison results
        """
        if not baseline_response or not test_response:
            return {'different': False, 'details': 'Invalid responses for comparison'}

        comparison = {
            'different': False,
            'status_code_changed': False,
            'content_length_diff': 0,
            'details': ''
        }

        # Compare status codes
        if baseline_response.status_code != test_response.status_code:
            comparison['different'] = True
            comparison['status_code_changed'] = True
            comparison['details'] += f"Status code changed: {baseline_response.status_code} -> {test_response.status_code}. "

        # Compare content length
        baseline_length = len(baseline_response.text)
        test_length = len(test_response.text)
        comparison['content_length_diff'] = test_length - baseline_length

        # If content length differs significantly, flag it
        if abs(comparison['content_length_diff']) > 50:
            comparison['different'] = True
            comparison['details'] += f"Content length difference: {comparison['content_length_diff']} characters. "

        # If no specific details were added but differences were detected
        if comparison['different'] and not comparison['details']:
            comparison['details'] = "Responses differ but no specific details identified."

        return comparison
