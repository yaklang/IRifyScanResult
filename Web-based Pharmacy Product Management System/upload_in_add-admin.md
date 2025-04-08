

# Title: [file Upload] in [Web-based Pharmacy Product Management System] <= [v1.0]

# **BUG_Author:** [yaklang. io, IRify, Yakit]

## Product Information
- **Vendor Homepage:** [link](https://www.sourcecodester.com/php/17883/web-based-product-alert-system.html)
- **Software Link:** [download-link](https://www.sourcecodester.com/sites/default/files/download/Senior%20Walter/product_expiry.zip)
- **Affected Version:** [<= v1.0]

- **BUG Author:** yaklang. io, IRify 

## Vulnerability Details
### Vulnerable Files
* `add-admin.php` 
### Vulnerability Type
Unrestricted File Upload
### Root Cause

```php
// add-admin.php:28
$file_type = $_FILES['avatar']['type']; //returns the mimetype
$allowed = array("image/jpg", "image/gif","image/jpeg", "image/webp","image/png");
if(!in_array($file_type, $allowed)) {
$_SESSION['error'] ='Only jpg,jpeg,Webp, gif, and png files are allowed. ';

// exit();

}else{
$image= addslashes(file_get_contents($_FILES['avatar']['tmp_name']));
$image_name= addslashes($_FILES['avatar']['name']);
$image_size= getimagesize($_FILES['avatar']['tmp_name']);
move_uploaded_file($_FILES["avatar"]["tmp_name"],"uploadImage/" . $_FILES["avatar"]["name"]);			
$location="uploadImage/" . $_FILES["avatar"]["name"];
		
```

### Impact
Remote Code Execution (RCE), Cross-Site Scripting (XSS), System Compromise

## Description
1. **Vulnerability Details:**

- The system fails to properly validate uploaded file types and content
- Relies solely on client-controllable MIME type checking
- No file extension validation implemented
- Upload directory lacks proper permission restrictions
- Predictable filenames enable direct access and overwrite attacks

2. **Attack Vectors:**

- Attacker can bypass MIME check by modifying HTTP requests
- Upload PHP files for remote code execution
- Upload malicious HTML/JS files for XSS attacks
- Large file uploads may cause denial of service

3. **Attack Payload Examples:**


```php
// Basic PHP webshell
<?php system($_GET['cmd']); ?>
// PHP file disguised as image
GIF89a;
<?php phpinfo(); ?>
```

## Code Scan
## Code Scan 
this vulnerability find by [IRify](ssa.to) :
![image.png](https://s2.loli.net/2025/04/08/exaTK6XMfURPIkZ.png)

## Proof of Concept
this valnerability validation by [Yakit](https://www.yaklang.io/)
Path: `/product_expiry/add-admin.php`
![image.png](https://s2.loli.net/2025/04/08/eTLIqohPxF6UZuX.png)
Send `phpinfo();` eval work. 
![image.png](https://s2.loli.net/2025/04/08/9PAcniJxm1trLqV.png)

## Suggested Repairs
1. **Whitelist Validation:**
```php
$allowed_ext = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
$file_ext = strtolower(pathinfo($_FILES['avatar']['name'], PATHINFO_EXTENSION));
if(!in_array($file_ext, $allowed_ext)) {
    die("Invalid file type");
}
```
2. **Content Verification:**
```php
if(!@getimagesize($_FILES['avatar']['tmp_name'])) {
    die("Invalid image file");
}
```
3. **Secure Storage Measures:**
- Rename files with random strings
- Set upload directory to non-executable
- Store file paths in database instead of using original names
- Implement file size limits
4. **Additional Recommendations:**
- Implement CSRF protection
- Log all upload activities
- Consider using cloud storage services
## Additional Information
1. This vulnerability affects all system users
2. Successful exploitation can lead to complete system compromise
3. Immediate upgrade to v1.1 or later is recommended
4. Temporary mitigation measures:
   - Disable file upload functionality
   - Inspect uploadImage directory for suspicious files
   - Review server logs for suspicious activities
   - Configure server to prevent PHP execution in upload directory
For comprehensive security assessment, engage professional cybersecurity teams for penetration testing and code audit.