
# Title: [sql-inject] in [Web-based Pharmacy Product Management System] <= [v1.0]

# **BUG_Author:** [yaklang. io, IRify, Yakit]

## Product Information
- **Vendor Homepage:** [link](https://www.sourcecodester.com/php/17883/web-based-product-alert-system.html)
- **Software Link:** [download-link](https://www.sourcecodester.com/sites/default/files/download/Senior%20Walter/product_expiry.zip)
- **Affected Version:** [<= v1.0]

- **BUG Author:** yaklang. io, IRify 

## Vulnerability Details
### Vulnerable Files
- `edit-admin.php`
* `activity-log.php`
* `add-admin.php`
* `add-category.php`
* `add-product.php`
* `add-sales.php`
* `add-stock.php`
* `add-supplier.php`
* `backup_db.php`
* `changepassword.php`
* `edit-photo.php`
* `edit-product.php`
* `edit-profile.php`
* `index.php`
* `sales-record.php`
* `stock-record.php`
* `student-record.php`
* `user-record.php`

### Vulnerability Type
SQL Injection Vulnerability (CWE-89: SQL Injection)

### Root Cause
In many php file start, have this email check:
```php
<?php
include('topbar.php');
if(empty($_SESSION['login_email']))
    {   
      header("Location: login.php"); 
    }
    else{
	}
      
$email = $_SESSION["login_email"];
//fetch user data
$stmt = $dbh->query("SELECT * FROM users where email='$email'");
$row_user = $stmt->fetch();
```

this email set by: `login.php` 
```php
<?php
include('topbar.php');

if(isset($_POST['btnlogin']))
{
  $status ="1";
//login
$sql = "SELECT * FROM `users` WHERE `email`=? AND `password`=? AND `status`=?";
			$query = $dbh->prepare($sql);
			$query->execute(array($_POST['txtemail'],$_POST['txtpassword'],$status));
			$row = $query->rowCount();
			$fetch = $query->fetch();
			if($row > 0) {
			$_SESSION['login_email'] = $fetch['email'];
			$_SESSION['login_groupname'] = $fetch['groupname'];
      $_SESSION['login_fullname'] = $fetch['fullname'];
		  $_SESSION['logged']=time();
		
```
This data select from database. 
We can find `add-admin.php`, this file insert data to users table, and the emial field can control by Post Argument.
```php

if(isset($_POST["btncreate"]))
{

$name = $_POST['txtfullname'];
$email = $_POST['txtemail'];
$password = $_POST['txtpassword'];
$phone = $_POST['txtphone'];
$groupname = $_POST['cmdtype'];
$last_ip="NA";
$lastaccess="NA";
$status="1";

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
			
///check if email already exist
$stmt = $dbh->prepare("SELECT * FROM users WHERE email=?");
$stmt->execute([$email]); 
$user = $stmt->fetch();

if ($user) {
$_SESSION['error'] ='Email Already Exist in our Database ';

} else {
 //Add User details
$sql = 'INSERT INTO users(email,password,fullname,lastaccess,last_ip,groupname,phone,status,photo) VALUES(:email,:password,:fullname,:lastaccess,:last_ip,:groupname,:phone,:status,:photo)';
$statement = $dbh->prepare($sql);
$statement->execute([
	':email' => $email,
	':password' => $password,
	':fullname' => $name,
	':lastaccess' => $lastaccess,
	':last_ip' => $last_ip,
		':groupname' => $groupname,
    ':phone' => $phone,
		':status' => $status,
		':photo' => $location

]);
```
So this `$_SESSION['login_email']` can control by user. 



### Impact
- Unauthorized access to database information
- Potential exposure of sensitive information (such as user passwords)
- Possible database corruption or data manipulation


## Description
1. **Vulnerability Details:**
   - In the this php code, username parameter is directly concatenated into SQL statement
   - Both locations contain classic SQL injection vulnerabilities
   - No input validation or escaping mechanisms implemented

2. **Attack Vectors:**
   - Attackers can manipulate SQL query structure using special characters
   - Additional information can be extracted using UNION queries
   - Database information can be obtained through boolean-based blind injection
   - Error-based injection might reveal more information

3. **Attack Payload Examples:**
   sql: `"SELECT * FROM tblproduct where product_name='$name'"`
   ```sql
   ' or '1' = '1
   ' union select ... where '1'='1 
   .... 
   ```
## Code Scan 

this vulnerability find by [IRify](ssa.to) :

![image.png](https://s2.loli.net/2025/04/08/B6dZDyrGOzXulsq.png)




## Proof of Concept
### Poc 1
this valnerability validation by [Yakit](https://www.yaklang.io/)
Use yakit modify `add-admin.php` post request: 

![image.png](https://s2.loli.net/2025/04/08/zmnwptMLJ3dAoue.png)


We can  add user email is `'1 or '1'='1`
![image.png](https://s2.loli.net/2025/04/08/nZm5PvYDNdAhcRX.png)


We can see the data load first line info to $row_user 
![image.png](https://s2.loli.net/2025/04/08/kvuVb5tWcAJyq8n.png)

![image.png](https://s2.loli.net/2025/04/08/B2F3DZswMeblCNg.png)

This eamil `' or '1' = '1` fullname should be `aaa` , but we use sql-inject get first line data, get `Goodness Monday`
![image.png](https://s2.loli.net/2025/04/08/q9YbDaOS1vI2EBz.png)



## Suggested Repairs
1. Implement Prepared Statements
2. Input Validation
3. Security Recommendations
   - Implement principle of least privilege
   - Encrypt sensitive data storage
   - Implement WAF protection
   - Conduct regular security audits
   - Use ORM frameworks for database operations
## Additional Information
- Refer to OWASP SQL Injection Prevention Guide
- Consider using modern frameworks like MyBatis or Hibernate
- Implement logging and monitoring mechanisms
- References:
  - OWASP SQL Injection Prevention Cheat Sheet
  - CWE-89: SQL Injection
  - CERT Oracle Secure Coding Standard for Java

The severity of this vulnerability is HIGH, and immediate remediation is recommended as it poses a serious threat to the system's data security.

Mitigation Timeline:
- Immediate: Implement prepared statements
- Short-term: Add input validation
- Long-term: Consider migrating to an ORM framework

This vulnerability requires immediate attention due to its potential for significant data breach and system compromise.