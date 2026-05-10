# WebScan Pro — Sample Finding Format

This document illustrates the structure of findings produced by WebScan Pro.

---

## Finding: Missing Content-Security-Policy Header

| Field | Value |
|-------|-------|
| **Type** | Missing Security Header |
| **Severity** | HIGH |
| **Header** | Content-Security-Policy |
| **URL** | https://example.com |
| **CWE** | CWE-16 (Configuration) |
| **OWASP** | A05:2021 – Security Misconfiguration |

**Description:**  
The `Content-Security-Policy` header is absent from HTTP responses. This header controls which resources the browser is allowed to load, significantly reducing the risk of Cross-Site Scripting (XSS) and data injection attacks.

**Impact:**  
Without CSP, an attacker who achieves XSS can execute arbitrary JavaScript, steal session cookies, redirect users, or perform actions on their behalf.

**Recommendation:**  
Add a `Content-Security-Policy` header to all HTTP responses. Start with a report-only policy:

```
Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self'; report-uri /csp-report
```

Then tighten to enforcement mode once the policy is validated.

---

## Finding: Sensitive Path Exposed

| Field | Value |
|-------|-------|
| **Type** | Sensitive Path Exposed |
| **Severity** | HIGH |
| **Path** | `/.git/config` |
| **Status Code** | 200 OK |
| **OWASP** | A01:2021 – Broken Access Control |

**Description:**  
The `.git/config` file is publicly accessible. This file contains repository metadata including remote URLs, which may expose internal infrastructure details or credentials stored in repository history.

**Impact:**  
Attackers can reconstruct source code, extract hardcoded credentials, and understand the codebase structure.

**Recommendation:**  
Block access to `.git/` directories at the web server level:

```nginx
# Nginx
location ~ /\.git {
    deny all;
    return 404;
}
```

```apache
# Apache
RedirectMatch 404 /\.git
```

---

## Risk Score Calculation

| Severity | Weight | Count | Subtotal |
|----------|--------|-------|---------|
| CRITICAL | × 10   | 0     | 0       |
| HIGH     | × 5    | 3     | 15      |
| MEDIUM   | × 2    | 3     | 6       |
| LOW      | × 1    | 2     | 2       |
| **Total**|        |       | **23**  |

**Risk Bands:**
- 0–4: Informational
- 5–9: Low Risk
- 10–19: Medium Risk
- 20–39: High Risk
- 40+: Critical Risk
