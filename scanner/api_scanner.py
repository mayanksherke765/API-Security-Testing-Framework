import requests
import time
from urllib.parse import urljoin


def scan_api(url):

    results = {}

    security_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-XSS-Protection"
    ]

    sensitive_paths = [
        "/admin",
        "/login",
        "/auth",
        "/swagger",
        "/api-docs",
        "/debug",
        "/config",
        "/health",
        "/status"
    ]

    try:
        start_time = time.time()

        response = requests.get(url)

        end_time = time.time()

        response_time = round(end_time - start_time, 2)

        headers = dict(response.headers)

        results["status"] = "API Reachable"
        results["status_code"] = response.status_code
        results["response_time"] = response_time

        # HTTPS Check
        if url.startswith("https://"):
            results["https_enabled"] = "Yes"
        else:
            results["https_enabled"] = "No"

        # Authorization Header Check
        if "Authorization" in headers:
            results["auth_header"] = "Present"

            auth_value = headers.get("Authorization", "")

            if "Bearer" in auth_value:
                results["jwt_token"] = "Bearer Token Detected"
            else:
                results["jwt_token"] = "Unknown Auth Method"

        else:
            results["auth_header"] = "Not Found"
            results["jwt_token"] = "Not Detected"

        # Authentication Check
        if response.status_code == 401:
            results["authentication"] = "Required"
        else:
            results["authentication"] = "Not Required"

        # Missing Security Headers
        missing_headers = []

        for header in security_headers:
            if header not in headers:
                missing_headers.append(header)

        results["missing_headers"] = missing_headers

        # Rate Limiting Detection
        success_requests = 0

        for _ in range(10):

            test_response = requests.get(url)

            if test_response.status_code == 200:
                success_requests += 1

        if success_requests == 10:
            results["rate_limiting"] = "Not Detected"
        else:
            results["rate_limiting"] = "Detected"

        # ==========================
        # Sensitive Endpoint Discovery
        # ==========================

        discovered_endpoints = []

        for path in sensitive_paths:

            endpoint_url = urljoin(url, path)

            try:
                endpoint_response = requests.get(endpoint_url)

                if endpoint_response.status_code in [200, 301, 302, 403]:
                    discovered_endpoints.append(path)

            except:
                pass

        results["discovered_endpoints"] = discovered_endpoints

        # Recommendations
        recommendations = []

        if results["https_enabled"] == "No":
            recommendations.append(
                "Enable HTTPS to secure API communication."
            )

        if results["authentication"] == "Not Required":
            recommendations.append(
                "Implement authentication for sensitive APIs."
            )

        if results["auth_header"] == "Not Found":
            recommendations.append(
                "Use Authorization headers for secure access."
            )

        if len(missing_headers) > 0:
            recommendations.append(
                "Add missing security headers."
            )

        if results["rate_limiting"] == "Not Detected":
            recommendations.append(
                "Implement API rate limiting to prevent abuse."
            )

        if len(discovered_endpoints) > 0:
            recommendations.append(
                "Restrict access to sensitive API endpoints."
            )

        results["recommendations"] = recommendations

        # Risk Score
        risk_score = 0

        if len(missing_headers) > 2:
            risk_score += 2

        if results["https_enabled"] == "No":
            risk_score += 2

        if results["auth_header"] == "Not Found":
            risk_score += 1

        if results["authentication"] == "Not Required":
            risk_score += 1

        if results["rate_limiting"] == "Not Detected":
            risk_score += 2

        if len(discovered_endpoints) > 0:
            risk_score += 2

        if risk_score <= 2:
            results["risk_level"] = "Low"

        elif risk_score <= 5:
            results["risk_level"] = "Medium"

        else:
            results["risk_level"] = "High"

    except Exception as e:

        results["status"] = "API Unreachable"
        results["error"] = str(e)

    return results