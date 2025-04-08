

# Title: [sql-inject] in [Web-based Pharmacy Product Management System] <= [v1.0]

# **BUG_Author:** [yaklang. io, IRify, Yakit]

## Product Information
- **Vendor Homepage:** [link](https://www.sourcecodester.com/php/17883/web-based-product-alert-system.html)
- **Software Link:** [download-link](https://www.sourcecodester.com/sites/default/files/download/Senior%20Walter/product_expiry.zip)
- **Affected Version:** [<= v1.0]

- **BUG Author:** yaklang. io, IRify 

## Vulnerability Details
### Vulnerable Files
- `search\search_stock.php`
- `search\search_sales.php`

### Vulnerability Type
SQL Injection Vulnerability (CWE-89: SQL Injection)



### Root Cause
The code directly concatenates user input into SQL query strings without any parameterization or input validation, allowing attackers to inject malicious SQL code.
// search\search_stock. php
```php
<?php
include '../database/connect.php';

$name = $_REQUEST['name'];
if ($name !== "") {
	$stmt = $dbh->query("SELECT * FROM tblproduct where product_name='$name'");
	$row = $stmt->fetch();
	$expirydate = $row["expirydate"];
	$stock = $row["qty"];
	$category = $row["category"];
	$productID = $row["productID"];

}
// Store it in a array
$result = array("$expirydate", "$stock","$category","$productID");
// Send in JSON encoded form
$myJSON = json_encode($result);
echo $myJSON;
?>
```
// search\search_sales. php
```php
<?php
include '../database/connect.php';

$name = $_REQUEST['name'];
if ($name !== "") {
	
	$stmt = $dbh->query("SELECT * FROM tblproduct where product_name='$name'");
	$row = $stmt->fetch();
	$expirydate = $row["expirydate"];
	$stock = $row["qty"];
	$category = $row["category"];
	$productID = $row["productID"];
	$unitPrice = $row["price"];

}
// Store it in a array
$result = array("$expirydate", "$stock","$category","$productID","$unitPrice");
// Send in JSON encoded form
$myJSON = json_encode($result);
echo $myJSON;
?>
```

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
![](https://s2.loli.net/2025/04/02/G1ZoueDrVOjBF3n.png)


## Proof of Concept

this valnerability validation by [Yakit](https://www.yaklang.io/)

1. **Authentication Bypass:**
   ```sql
   ' or '1' = '1
   ```

/search/search_stock. php
![](https://s2.loli.net/2025/04/02/8tCvKqrg5slweFM.png)

/search/search_sales. php
![](https://s2.loli.net/2025/04/02/vWhSyXrsF6qxmJf.png)

2. **Information Extraction:**
   ```sql
   ' UNION SELECT 1,2,3,4,database(),user(),version(),table_name FROM information_schema.tables WHERE '1'='1
   ```
   This targets specific user information while maintaining the single-row result.
![](https://s2.loli.net/2025/04/02/Bcbw371lhKCOUZy.png)

## Suggested Repairs
1. Implement Prepared Statements
   ```php
    $stmt = $pdo->prepare("SELECT * FROM tblproduct WHERE product_name = ?");
    $stmt->execute([$name]);
   ```

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