# SSD Assignment - Secure Web Application
**Group - 68**

## 1. Team Members
* R A D P Ranathunga - IT23217386
* D H L N Jayalath - IT23202368
* N G N Tharuka - IT23157200
* J M U I Jayasundara - IT23233676

## 2. Project Links
* **Original Project Repository:** 
  * Web: https://github.com/Daniru12/WildSafe-web
  * Backend: https://github.com/Daniru12/WildSafe-back
* **Modified Project Repository:** 
  * Web: https://github.com/ishani2924/SSD_Secure_Web
  * Backend: https://github.com/ishani2924/SSD_Secure_Back

## 3. Video Presentation
* **YouTube Video Link:** https://youtu.be/W5c5BX1RgK4 
  * *Description:* This video describes the vulnerabilities found, the fixes implemented, and the OAuth/Open ID connect implementation.

## 4. Project Vulnerabilities & Fixes

Below is a summary of the vulnerabilities identified in the original project and how they were mitigated in the modified version.

| Vulnerability Type | Location/Description in Original Project | Implemented Fix |
| :--- | :--- | :--- |
| **Cross-Site Scripting (XSS)** | User inputs in forms (e.g., incident reporting, registration) were directly processed and reflected on the frontend without proper sanitization. | Added the `xss` library to sanitize user inputs on the backend. Implemented Content Security Policy (CSP) headers using `helmet` to prevent execution of unauthorized scripts on the client-side. |
| **Injection (NoSQL)** | Authentication routes (`/login`, `/register`) were vulnerable to NoSQL injection because they accepted objects (e.g., MongoDB operators like `{"$gt": ""}`) as valid credentials. | Added strict type checking (e.g., verifying `typeof req.body.email === 'string'`) in `authController.js` and introduced a `sanitizeInput` middleware to automatically strip MongoDB query operators (`$`) from incoming requests. |
| **Broken Authentication** | The login and registration endpoints lacked rate limiting, making them vulnerable to brute-force attacks. | Applied `express-rate-limit` (`authLimiter`) to authentication routes to throttle excessive requests. Integrated Google OAuth 2.0 (OpenID Connect) for secure, delegated authentication. |
| **Cross-Site Request Forgery (CSRF)** | Sensitive API endpoints were exposed to cross-origin requests because CORS was too permissive and cookies lacked security attributes. | Configured strict CORS policies (whitelisting only the frontend domain), set secure cookie attributes (`sameSite: 'lax'`, `secure: true`), and relied on secure JWT authorization headers. |
| **Insecure Direct Object Reference (IDOR)** | API endpoints returning sensitive data did not always adequately verify if the requesting user had ownership or admin rights. | Strengthened `authMiddleware` and `roleMiddleware` to ensure users can only access their own data, and restricted sensitive management routes strictly to authorized roles (e.g., admins or rangers). |
| **Security Misconfiguration** | The server leaked its tech stack via the `X-Powered-By` header, lacked Anti-Clickjacking headers, and did not enforce HTTPS. | Integrated `helmet` to remove `X-Powered-By`, added `X-Frame-Options` (`frameguard`) to prevent clickjacking, applied `X-Content-Type-Options: nosniff`, and enforced HTTP Strict Transport Security (HSTS). |

### OAuth / OpenID Connect Implementation
* **Details:** Implemented Google Login using `passport-google-oauth20` to securely handle user identity verification. A dedicated route redirects users to Google's consent screen. Upon a successful callback, the backend validates the OpenID profile and issues a JSON Web Token (JWT) combined with HTTP-only secure cookies.

---

