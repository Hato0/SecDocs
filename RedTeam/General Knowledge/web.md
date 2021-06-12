## Web Knowledge 
#### SQL injection
A SQL injection (SQLi) is a type of security exploit in which the attacker adds Structured Query Language (SQL) code to a Web form input box in order to gain access to unauthorized resources or make changes to sensitive data. An SQL query is a request for some action to be performed on a database. When executed correctly, a SQL injection can expose intellectual property, the personal information of customers, administrative credentials or private business details.

###### SQLi Basics
Here will be some basics informations to get when you have a successfull injection

- SQL injection attack, querying the database type and version on Oracle
	- Depending on the DB you can get the version as follow:
		- Microsoft, MySQL
		   `SELECT @@version`
		- Oracle
		   `SELECT * FROM v$version`
		- PostgreSQL
			`SELECT version()`
- SQL injection attack, listing the database contents 
	- Non-Oracle DB 
		`select * from information\_schema.tables`
	- Oracle DB
		`select * from all_tables`

###### Union SQL attack 
These attacks are perform to extract data using the same amount of row than the initial result could display. For this attack, working conditions are:
-   The individual queries must return the same number of columns.
-   The data types in each column must be compatible between the individual queries

You can have those following examples : 

- Determining the number of columns returned by the query
	- ```' union select NULL-- ```
	    *increasing number of NULL value until values are actually return*
	- ```' order by 1-- ```
		*increasing the int value until an error occured*
- Finding a column containing text
	- ``` union select 'a', NULL, NULL, ...--```
		*Add as many null as you need to match the number of columns*
- Retrieving data from other tables
	- ``` union select CHAMP1, CHAMP2, .... from TABLE_NAME--```
	    *Again add as many null value as needed* 
- Retrieving multiple values in a single column
	- ``` union select CHAMP1 || 'SEPERATOR' || CHAMP2 .... from TABLE_NAME--```
		*Very usefull when you only have the capacity to extract data from a uniq column*
		

- Blind SQL injection with conditional responses
- Blind SQL injection with conditional errors
- Blind SQL injection with time delays
- Blind SQL injection with time delays and information retrieval
- Blind SQL injection with out-of-band interaction
- Blind SQL injection with out-of-band data exfiltration
- SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
- SQL injection vulnerability allowing login bypass

###### How to prevent them 

If a SQL injection attack is successfully carried out, the damage could be expensive in terms of resources and customer trust. That is why detecting this type of attack in a timely manner is important. Web application firewalls (WAF) are the most common tool used to filter out SQLi attacks. WAFs are based on a library of updated attack signatures and can be configured to flag malicious SQL queries.

In order to prevent a SQL injection attack from occurring in the first place, developers can follow these practices:

-   Avoid SQL statements that allow user input, choose prepared statements and parameterized queries instead.
-   Perform input validation, or sanitization, for user-provided arguments.
-   Do not leave sensitive data in plaintext format, or use encryption.
-   Limit database permissions, privileges and capabilities to the bare minimum.
-   Keep databases updated on security patches.
-   Routinely test the security measures of applications that rely on databases.
-   Remove the display of database error messages to the users.


#### Cross-site scripting
- Reflected XSS into HTML context with nothing encoded
- Reflected XSS into HTML context with most tags and attributes blocked
- Reflected XSS into HTML context with all tags blocked except custom ones
- Reflected XSS with event handlers and href attributes blocked
- Reflected XSS with some SVG markup allowed
- Reflected XSS into attribute with angle brackets HTML-encoded
- Stored XSS into anchor href attribute with double quotes HTML-encoded
- Reflected XSS in canonical link tag
- Reflected XSS into a JavaScript string with single quote and backslash escaped
- Reflected XSS into a JavaScript string with angle brackets HTML encoded
- Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped
- Reflected XSS in a JavaScript URL with some characters blocked
- Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped
- Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped
- Reflected XSS with AngularJS sandbox escape without strings
- Reflected XSS with AngularJS sandbox escape and CSP
- Stored XSS into HTML context with nothing encoded
- DOM XSS in document.write sink using source location.search
- DOM XSS in document.write sink using source location.search inside a select element
- DOM XSS in innerHTML sink using source location.search
- DOM XSS in jQuery anchor href attribute sink using location.search source
- DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded
- Reflected DOM XSS
- Stored DOM XSS
- Exploiting cross-site scripting to steal cookies
- Exploiting cross-site scripting to capture passwords
- Exploiting XSS to perform CSRF
- Reflected XSS protected by CSP, with dangling markup attack
- Reflected XSS protected by very strict CSP, with dangling markup attack
- Reflected XSS protected by CSP, with CSP bypass
#### Cross-site request forgery (CSRF)
- CSRF vulnerability with no defenses
- CSRF where token validation depends on request method
- CSRF where token validation depends on token being present
- CSRF where token is not tied to user session
- CSRF where token is tied to non-session cookie
- CSRF where token is duplicated in cookie
- CSRF where Referer validation depends on header being present
- CSRF with broken Referer validation
#### Clickjacking
- Basic clickjacking with CSRF token protection
- Clickjacking with form input data prefilled from a URL parameter
- Clickjacking with a frame buster script
- Exploiting clickjacking vulnerability to trigger DOM-based XSS
- Multistep clickjacking
#### DOM-based vulnerabilities
- DOM XSS using web messages
- DOM XSS using web messages and a JavaScript URL
- DOM XSS using web messages and JSON.parse
- DOM-based open redirection
- DOM-based cookie manipulation
- Exploiting DOM clobbering to enable XSS
- Clobbering DOM attributes to bypass HTML filters
#### Cross-origin resource sharing (CORS)
- CORS vulnerability with basic origin reflection
- CORS vulnerability with trusted null origin
- CORS vulnerability with trusted insecure protocols
- CORS vulnerability with internal network pivot attack
#### XML external entity (XXE) injection
- Exploiting XXE using external entities to retrieve files
- Exploiting XXE to perform SSRF attacks
- Blind XXE with out-of-band interaction
- Blind XXE with out-of-band interaction via XML parameter entities
- Exploiting blind XXE to exfiltrate data using a malicious external DTD
- Exploiting blind XXE to retrieve data via error messages
- Exploiting XXE to retrieve data by repurposing a local DTD
- Exploiting XInclude to retrieve files
- Exploiting XXE via image file upload
#### Server-side request forgery (SSRF)
- Basic SSRF against the local server
- Basic SSRF against another back-end system
- SSRF with blacklist-based input filter
- SSRF with whitelist-based input filter
- SSRF with filter bypass via open redirection vulnerability
- Blind SSRF with out-of-band detection
- Blind SSRF with Shellshock exploitation
#### HTTP request smuggling
- HTTP request smuggling, basic CL.TE vulnerability
- HTTP request smuggling, basic TE.CL vulnerability
- HTTP request smuggling, obfuscating the TE header
- HTTP request smuggling, confirming a CL.TE vulnerability via differential responses
- HTTP request smuggling, confirming a TE.CL vulnerability via differential responses
- Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability
- Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability
- Exploiting HTTP request smuggling to reveal front-end request rewriting
- Exploiting HTTP request smuggling to capture other users' requests
- Exploiting HTTP request smuggling to deliver reflected XSS
- Exploiting HTTP request smuggling to perform web cache poisoning
- Exploiting HTTP request smuggling to perform web cache deception
#### OS command injection
- OS command injection, simple case
- Blind OS command injection with time delays
- Blind OS command injection with output redirection
- Blind OS command injection with out-of-band interaction
- Blind OS command injection with out-of-band data exfiltration
#### Server-side template injection
- Basic server-side template injection
- Basic server-side template injection (code context)
- Server-side template injection using documentation
- Server-side template injection in an unknown language with a documented exploit
- Server-side template injection with information disclosure via user-supplied objects
- Server-side template injection in a sandboxed environment
- Server-side template injection with a custom exploit
#### Directory traversal
- File path traversal, simple case
- File path traversal, traversal sequences blocked with absolute path bypass
- File path traversal, traversal sequences stripped non-recursively
- File path traversal, traversal sequences stripped with superfluous URL-decode
- File path traversal, validation of start of path
- File path traversal, validation of file extension with null byte bypass
#### Access control vulnerabilities
- Unprotected admin functionality
- Unprotected admin functionality with unpredictable URL
- User role controlled by request parameter
- User role can be modified in user profile
- URL-based access control can be circumvented
- Method-based access control can be circumvented
- User ID controlled by request parameter 
- User ID controlled by request parameter, with unpredictable user IDs
		
- User ID controlled by request parameter with data leakage in redirect 
- User ID controlled by request parameter with password disclosure
- Insecure direct object references
- Multi-step process with no access control on one step
		
- Referer-based access control
		
#### Authentication
- Username enumeration via different responses
- Username enumeration via subtly different responses
- Username enumeration via response timing
- Broken brute-force protection, IP block
- Username enumeration via account lock
- Broken brute-force protection, multiple credentials per request
- 2FA simple bypass
- 2FA broken logic
- 2FA bypass using a brute-force attack
- Brute-forcing a stay-logged-in cookie
- Offline password cracking
- Password reset broken logic
- Password reset poisoning via middleware
- Password brute-force via password change
#### WebSockets
- Manipulating WebSocket messages to exploit vulnerabilities
- Manipulating the WebSocket handshake to exploit vulnerabilities
- Cross-site WebSocket hijacking
#### Web cache poisoning
- Web cache poisoning with an unkeyed header
- Web cache poisoning with an unkeyed cookie
- Web cache poisoning with multiple headers
- Targeted web cache poisoning using an unknown header
- Web cache poisoning to exploit a DOM vulnerability via a cache with strict cacheability criteria
- Combining web cache poisoning vulnerabilities
- Web cache poisoning via an unkeyed query string
- Web cache poisoning via an unkeyed query parameter
- Parameter cloaking
- Web cache poisoning via a fat GET request
- URL normalization
- Cache key injection
- Internal cache poisoning
#### Insecure deserialization
- Modifying serialized objects
- Modifying serialized data types
- Using application functionality to exploit insecure deserialization
- Arbitrary object injection in PHP
- Exploiting Java deserialization with Apache Commons
- Exploiting PHP deserialization with a pre-built gadget chain
- Exploiting Ruby deserialization using a documented gadget chain
- Developing a custom gadget chain for Java deserialization
- Developing a custom gadget chain for PHP deserialization
- Using PHAR deserialization to deploy a custom gadget chain
#### Information disclosure
- Information disclosure in error messages
- Information disclosure on debug page
- Source code disclosure via backup files
- Authentication bypass via information disclosure
- Information disclosure in version control history
#### Business logic vulnerabilities
- Excessive trust in client-side controls
- High-level logic vulnerability
- Low-level logic flaw
- Inconsistent handling of exceptional input
- Inconsistent security controls
- Weak isolation on dual-use endpoint
- Insufficient workflow validation
- Authentication bypass via flawed state machine
- Flawed enforcement of business rules
- Infinite money logic flaw
- Authentication bypass via encryption oracle
#### HTTP Host header attacks
- Basic password reset poisoning
- Password reset poisoning via dangling markup
- Web cache poisoning via ambiguous requests
- Host header authentication bypass
- Routing-based SSRF
- SSRF via flawed request parsing
#### OAuth authentication
- Authentication bypass via OAuth implicit flow
- Forced OAuth profile linking
- OAuth account hijacking via redirect_uri
- Stealing OAuth access tokens via an open redirect
- Stealing OAuth access tokens via a proxy page
- SSRF via OpenID dynamic client registration
