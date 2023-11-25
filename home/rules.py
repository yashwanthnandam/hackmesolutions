import requests

class Rules:

    def __init__(self, domain, headers=None, cookies=None):
        self.domain = domain
        self.headers = headers   #response headers
        self.cookies = cookies
        self.rules = [
            {"rule_name": "check_csp", "rule_name_readable": "Check Csp"},
            {"rule_name": "check_secure_cookie_flag", "rule_name_readable": "Check Secure Cookie Flag"},
            {"rule_name": "check_http_only_cookie_flag", "rule_name_readable": "Check Http Only Cookie Flag"},
            {"rule_name": "check_domain_settings_for_cookies", "rule_name_readable": "Check Domain Settings For Cookies"},
            {"rule_name": "check_missing_http_header_referrer", "rule_name_readable": "Check Missing Http Header Referrer"},
            {"rule_name": "check_missing_http_header_x_content_type_options", "rule_name_readable": "Check Missing Http Header X Content Type Options"},
            {"rule_name": "check_x_frame_options_header", "rule_name_readable": "Check X Frame Options Header"},
            {"rule_name": "check_missing_csp_header", "rule_name_readable": "Check Missing Csp Header"},
            {"rule_name": "check_strict_transport_security_header", "rule_name_readable": "Check Strict Transport Security Header"},
            {"rule_name": "check_directory_listing", "rule_name_readable": "Check Directory Listing"},
            {"rule_name": "check_secure_communication", "rule_name_readable": "Check Secure Communication"},
            {"rule_name": "check_http_debug_methods", "rule_name_readable": "Check Http Debug Methods"},
            {"rule_name": "check_untrusted_certificates", "rule_name_readable": "Check Untrusted Certificates"},
            {"rule_name": "check_security_txt_file", "rule_name_readable": "Check Security Txt File"},
            {"rule_name": "check_robots_txt_file", "rule_name_readable": "Check Robots Txt File"},
            {"rule_name": "check_client_access_policies", "rule_name_readable": "Check Client Access Policies"},
            {"rule_name": "check_website_accessibility", "rule_name_readable": "Check Website Accessibility"}
        ]

        self.result = []

    def run_rules(self):
        all_count = len(self.rules)
        yes_count = 0
        for rule in self.rules:
            rule_name = rule["rule_name"]
            rule_name_readable = rule["rule_name_readable"]
            res_rule = getattr(self, rule_name)()
            self.result.append(
                {
                    "rule_name": rule_name_readable,
                    "rule_implemented": res_rule[0],
                    "rule_remarks": res_rule[1]
                }
            )
            if res_rule[0]:
                yes_count+=1

        yes_percent = (yes_count * 100 / all_count)
        if yes_percent > 95:
            score = 'A+'
        elif yes_percent <= 95 and yes_percent > 60:
            score = 'B+'
        else:
            score = 'D'

        return self.result, score

    def load_headers(self):
        try:
            import requests
            response = requests.head(self.domain)
            self.headers = response.headers
            return True
        except:
            return False
        
    def load_cookies(self):
        try:
            import requests
            response = requests.head(self.domain)
            self.cookies = response.cookies
            return True
        except:
            return False



    def check_csp(self):
        if not self.headers:
            self.load_headers()
        csp_header = self.headers.get("Content-Security-Policy", self.headers.get("Content-Security-Policy-Report-Only", None))
        if csp_header:
            # Check if CSP is implemented
            if "default-src 'none'" in csp_header:
                return False, "CSP is implemented but overly restrictive ('default-src' is 'none')."
            
            if "'unsafe-inline'" in csp_header or "'unsafe-eval'" in csp_header:
                return False, "CSP allows 'unsafe-inline' or 'unsafe-eval', which can be a security risk."
            
            # You can add more checks for specific directives or sources as needed

            return True, "CSP is properly implemented."

        return False, "CSP is not implemented on the website."

    def check_secure_cookie_flag(self):
        try:
            if not self.cookies:
                self.load_cookies()
            
            cookies = self.cookies

            secure_cookies = []
            insecure_cookies = []

            for cookie in cookies:
                if cookie.secure:
                    secure_cookies.append(cookie.name)
                else:
                    insecure_cookies.append(cookie.name)

            if insecure_cookies:
                return False, f"The following cookies are missing the 'Secure' flag: {', '.join(insecure_cookies)}"
            else:
                return True, "All cookies have the 'Secure' flag properly set."

        except Exception as e:
            return False, f"Error: {str(e)}"
        
    def check_http_only_cookie_flag(self):
        try:
            if not self.cookies:
                self.load_cookies()
            
            cookies = self.cookies

            non_http_only_cookies = []

            for cookie in cookies:
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    non_http_only_cookies.append(cookie.name)

            if non_http_only_cookies:
                return False, f"The following cookies are missing the 'HttpOnly' flag: {', '.join(non_http_only_cookies)}"
            else:
                return True, "All cookies have the 'HttpOnly' flag properly set."

        except Exception as e:
            return False, f"Error: {str(e)}"

    def check_domain_settings_for_cookies(self, allowed_domains=[]):
        try:
            if not self.cookies:
                self.load_cookies()
            
            cookies = self.cookies

            cookies_with_loose_domain = []

            for cookie in cookies:
                domain = cookie.domain
                if domain and not any(domain.endswith(allowed_domain) for allowed_domain in allowed_domains):
                    cookies_with_loose_domain.append(cookie.name)

            if cookies_with_loose_domain:
                return False, f"The following cookies have a too loose domain setting: {', '.join(cookies_with_loose_domain)}"
            else:
                return True, "All cookies have the correct domain settings."

        except Exception as e:
            return False, f"Error: {str(e)}"

    def check_missing_http_header_referrer(self):
        if not self.headers:
            self.load_headers()
        referrer_header = self.headers.get("Referrer-Policy", None)
        if referrer_header:
            return True, "Referrer-Policy header is properly implemented."
        return False, "Referrer-Policy header is missing."

    def check_missing_http_header_x_content_type_options(self):
        if not self.headers:
            self.load_headers()
        x_content_type_options_header = self.headers.get("X-Content-Type-Options", None)
        if x_content_type_options_header == "nosniff":
            return True, "X-Content-Type-Options header is properly implemented."
        return False, "X-Content-Type-Options header is missing or not set to 'nosniff'."
    
    def check_x_frame_options_header(self):
        if not self.headers:
            self.load_headers()
        x_frame_options_header = self.headers.get("X-Frame-Options", None)
        if x_frame_options_header:
            return True, "X-Frame-Options header is properly implemented."
        return False, "X-Frame-Options header is missing."

    def check_missing_csp_header(self):
        if not self.headers:
            self.load_headers()
        csp_header = self.headers.get("Content-Security-Policy", None)
        if csp_header:
            return True, "Content Security Policy header is properly implemented."
        return False, "Content Security Policy header is missing."

    def check_strict_transport_security_header(self):
        if not self.headers:
            self.load_headers()
        hsts_header = self.headers.get("Strict-Transport-Security", None)
        if hsts_header:
            return True, "Strict-Transport-Security header is properly implemented."
        return False, "Strict-Transport-Security header is missing."

    def check_directory_listing(self):
        try:
            response = requests.get(self.domain)
            if "Index of /" in response.text:
                return False, "Directory listing is enabled."
            return True, "Directory listing is disabled."
        except:
            return False, "Error while checking directory listing."

    def check_secure_communication(self):
        try:
            response = requests.get(self.domain)
            if response.url.startswith("https://"):
                return True, "Secure communication is enforced."
            return False, "The website is not using HTTPS (secure communication)."
        except:
            return False, "Error while checking secure communication."

    def check_http_debug_methods(self):
        try:
            response = requests.options(self.domain)
            if "TRACE" in response.headers.get("allow", "").upper():
                return False, "HTTP debug methods are enabled."
            return True, "HTTP debug methods are disabled."
        except:
            return False, "Error while checking HTTP debug methods."

    def check_untrusted_certificates(self):
        try:
            response = requests.get(self.domain, verify=False)
            return False, "Untrusted certificates are in use."
        except requests.exceptions.SSLError:
            return True, "Certificates are properly trusted."

    def check_security_txt_file(self):
        try:
            response = requests.get(f"{self.domain}/.well-known/security.txt")
            if response.status_code == 200:
                return True, "Security.txt file is present."
            return False, "Security.txt file is absent."
        except:
            return False, "Error while checking for security.txt file."

    def check_robots_txt_file(self):
        try:
            response = requests.get(f"{self.domain}/robots.txt")
            if response.status_code == 200:
                return True, "Robots.txt file is present."
            return False, "Robots.txt file is absent."
        except:
            return False, "Error while checking for robots.txt file."
    
    def check_client_access_policies(self):
        if not self.headers:
            self.load_headers()

        headers = self.headers
        # Check for specific HTTP headers that control client access policies
        if "X-Content-Type-Options" in headers and "Content-Security-Policy" in headers:
            return True, "Client access policies are properly configured"
        return False, "Client access policies are not properly configured"

    def check_website_accessibility(self):
        if not self.headers:
            self.load_headers()

        headers = self.headers
        if "Content-Length" in headers and "200" in headers["Content-Length"]:
            return True, "Website is accessible"
        return False, "Website is not accessible (HTTP status code is not 200)"