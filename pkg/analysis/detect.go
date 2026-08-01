package analysis

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/L9Lenny/caddy-analyzer/pkg/types"
)

type DetectionType string

const (
	DetSQLInjection    DetectionType = "sql_injection"
	DetNoSQLi          DetectionType = "nosql_injection"
	DetXSS             DetectionType = "xss"
	DetSSTI            DetectionType = "ssti"
	DetSSRF            DetectionType = "ssrf"
	DetRCE             DetectionType = "rce"
	DetPathTraversal   DetectionType = "path_traversal"
	DetLFIWrapper      DetectionType = "lfi_wrapper_abuse"
	DetGraphQL         DetectionType = "graphql_introspection"
	DetLog4j           DetectionType = "log4j_jndi"
	DetSensitiveFile   DetectionType = "sensitive_file_probe"
	DetAdminProbe      DetectionType = "admin_probe"
	DetWPProbe         DetectionType = "wordpress_probe"
	DetCGIProbe        DetectionType = "cgi_probe"
	DetScanner         DetectionType = "scanner"
	DetXXE             DetectionType = "xxe"
	DetOpenRedirect    DetectionType = "open_redirect"
	DetLDAPInjection   DetectionType = "ldap_injection"
	DetXPathInjection  DetectionType = "xpath_injection"
	DetCRLFInjection   DetectionType = "crlf_injection"
	DetProtoPollution  DetectionType = "prototype_pollution"
	DetSSIInjection    DetectionType = "ssi_injection"
	DetBruteForce      DetectionType = "brute_force"
	DetCredScan        DetectionType = "credential_scanning"
)

type Detection struct {
	Type   DetectionType `json:"type"`
	IP     string        `json:"ip"`
	URI    string        `json:"uri"`
	Status int           `json:"status"`
	Desc   string        `json:"description"`
}

type IPDetStats struct {
	AuthFailures int
	NotFound     int
	Total        int
}

type Detector struct {
	patterns []struct {
		re    *regexp.Regexp
		dtype DetectionType
		desc  string
	}
	ipStats map[string]*IPDetStats
}

func NewDetector() *Detector {
	return &Detector{
		patterns: compilePatterns(),
		ipStats:  make(map[string]*IPDetStats),
	}
}

func compilePatterns() []struct {
	re    *regexp.Regexp
	dtype DetectionType
	desc  string
} {
	var p []struct {
		re    *regexp.Regexp
		dtype DetectionType
		desc  string
	}

	add := func(pattern string, dtype DetectionType, desc string) {
		p = append(p, struct {
			re    *regexp.Regexp
			dtype DetectionType
			desc  string
		}{regexp.MustCompile(pattern), dtype, desc})
	}

	// SQL Injection
	add(`(?i)(\bUNION\s+(?:ALL\s+)?SELECT\b|\bSELECT\b\s+.{0,200}?\bFROM\b\s+\w)`, DetSQLInjection, "SQL injection: UNION SELECT")
	add(`(?i)(\bOR\s+1\s*=\s*1|1\s*=\s*1\s*--|\bOR\s+'1'\s*=\s*'1'|'(\s*OR\s*|\s*AND\s*)'1'='1|"(\s*OR\s*|\s*AND\s*)"1"="1)`, DetSQLInjection, "SQL injection: tautology")
	add(`(?i)('.{0,50}?--|\bDROP\s+TABLE\b|;\s*DROP\s+|DELETE\s+FROM\b|TRUNCATE\b)`, DetSQLInjection, "SQL injection: destructive")
	add(`(?i)(INFORMATION_SCHEMA|PG_CATALOG|MYSQL_HELP|SYSTEM_USER|CURRENT_USER|SESSION_USER|USER\s*\(\))`, DetSQLInjection, "SQL injection: system info")
	add(`(?i)(pg_sleep|SLEEP\s*\(|WAITFOR\s+DELAY|BENCHMARK\s*\(|DBMS_LOCK\.SLEEP|SIGN\s*\(|EXP\s*\(|POW\s*\(|IF\s*\(.*SLEEP|SLEEP\s*$)`, DetSQLInjection, "SQL injection: time-based blind")
	add(`(?i)(CONVERT\s*\(.*INT|CAST\s*\(.*INT|EXTRACTVALUE\s*\(|UPDATEXML\s*\(|GROUP_CONCAT\s*\()`, DetSQLInjection, "SQL injection: error-based")
	add(`(?i)(xp_cmdshell|sp_executesql|sp_makewebtask|OPENROWSET|OPENDATASOURCE|xp_regread|xp_regwrite|xp_enumdsn|xp_availablemedia|xp_fileexist|xp_subdirs|xp_dirtree)`, DetSQLInjection, "SQL injection: out-of-band / OS")
	add(`(?i)(INTO\s+(OUTFILE|DUMPFILE)|LOAD_FILE\s*\(|INFILE\s+)`, DetSQLInjection, "SQL injection: file operation")
	add(`(?i)(@@version|@@basedir|@@datadir|@@hostname|@@servername|@@langid|@@language|@@microsoftversion|@@max_connections)`, DetSQLInjection, "SQL injection: global variables")
	add(`(?i)(HAVING\s+\d+|ORDER\s+BY\s+\d+|GROUP\s+BY\s+\d+)`, DetSQLInjection, "SQL injection: column enumeration")
	add(`(?i)(CHAR\s*\(|ASCII\s*\(|SUBSTRING\s*\(|SUBSTR\s*\(|MID\s*\(|ORD\s*\()`, DetSQLInjection, "SQL injection: blind functions")
	add(`(?i)(EXEC\s+(xp_|sp_)|EXECUTE\s+(xp_|sp_))`, DetSQLInjection, "SQL injection: stored procedure")
	add(`(?i)(pg_sleep|pg_read_file|pg_read_binary_file|pg_ls_dir|COPY\s+.*\s+FROM\s+PROGRAM)`, DetSQLInjection, "SQL injection: postgres superuser")
	add(`(?i)(DECLARE\s+@|SET\s+@|EXEC\s*\(|EXECUTE\s*\()`, DetSQLInjection, "SQL injection: SQL Server variables")
	add(`(?i)(UNION\s+ALL\s+SELECT\s+NULL|UNION\s+SELECT\s+NULL)`, DetSQLInjection, "SQL injection: column number discovery")

	// NoSQL Injection
	add(`(?i)(\$ne|\$gt|\$gte|\$lt|\$lte|\$regex|\$where|\$exists|\$nin|\$in|\$all|\$elemMatch|\$size|\$mod|\$type|\$slice|\$comment|\$or|\$and|\$nor|\$not)`, DetNoSQLi, "NoSQL injection: MongoDB operators")
	add(`(?i)(%24ne|%24gt|%24gte|%24lt|%24lte|%24regex|%24where|%24exists|%24nin|%24in|%24all|%24elemMatch|%24size)`, DetNoSQLi, "NoSQL injection: URL-encoded operators")
	add(`(?i)('\s*\|\|\s*'1'\s*==\s*'1|'\s*\|\|\s*1\s*==\s*1|true\);\s*return\s+true)`, DetNoSQLi, "NoSQL injection: JavaScript eval")

	// XSS
	add(`(?i)(<script[^>]*>|<\/script>|<\s*script|<img[^>]*\s+src|<\s*img\s|<\s*iframe\s|<\s*body\s|<\s*input\s|<\s*svg\s|<\s*details\s|<\s*marquee\s|<\s*embed\s|<\s*object\s|<\s*video\s|<\s*audio\s|<\s*link\s+rel=\s*stylesheet|<\s*style[^>]*>|<\s*math\s|<\s*et\s|<\s*template\s|<<script|<<svg)`, DetXSS, "XSS: HTML tag injection")
	add(`(?i)(onerror\s*=|onload\s*=|onclick\s*=|onmouseover\s*=|onmouseout\s*=|onfocus\s*=|onblur\s*=|onsubmit\s*=|onreset\s*=|onchange\s*=|onkeydown\s*=|onkeypress\s*=|onkeyup\s*=|ondblclick\s*=|onabort\s*=|onbeforeunload\s*=|onhashchange\s*=|oninput\s*=|oninvalid\s*=|onplay\s*=|onprogress\s*=|onscroll\s*=|onselect\s*=|ontoggle\s*=|onwheel\s*=|onauxclick\s*=|ongotpointercapture\s*=|onlostpointercapture\s*=|onpointerdown\s*=|onpointermove\s*=|onpointerup\s*=|onpointerover\s*=|onpointerenter\s*=|onpointerleave\s*=|onpointerout\s*=|onpointercancel\s*=)`, DetXSS, "XSS: event handler")
	add(`(?i)(javascript:|vbscript:|livescript:|data:\s*text/html|data:\s*text/javascript|data:\s*application/x-javascript|data:\s*image/svg\+xml|data:\s*[^,]*,.*base64|blob:)`, DetXSS, "XSS: protocol handler")
	add(`(?i)(alert\s*\(|prompt\s*\(|confirm\s*\(|print\s*\(|setTimeout\s*\(|setInterval\s*\(|execScript\s*\(|Function\s*\(|setImmediate\s*\()`, DetXSS, "XSS: dangerous JS function")
	add(`(?i)(document\.cookie|document\.location|document\.write|document\.writeln|document\.domain|document\.URI|document\.URL|document\.baseURI|document\.referrer|document\.documentURI|\.innerHTML|\.outerHTML|window\.location|location\.href|location\.hash|location\.search|location\.pathname|location\.replace|navigator\.sendBeacon)`, DetXSS, "XSS: DOM access")
	add(`(?i)(String\.fromCharCode|String\.fromCodePoint|escape\s*\(|unescape\s*\(|encodeURI|decodeURI|atob\s*\(|btoa\s*\()`, DetXSS, "XSS: encoding/bypass function")
	add(`(?i)(expression\s*\(|-moz-binding|behavior\s*:|url\s*\(\s*javascript|progid:DXImageTransform|@import\s+url)`, DetXSS, "XSS: CSS expression")
	add(`(?i)(@import\s+url|@import\s+"[^"]*\.css|@charset\s+|@font-face\s*\{)`, DetXSS, "XSS: CSS import")
	add(`(?i)(<![CDATA\[|]]>|<\?xml|<\?php|<\?=)`, DetXSS, "XSS: XML/SSI injection")
	add(`(?i)(%3C|%3E|%22|%27|%0D|%0A|%09|%00|&#x?3[Cc]|&#x?3[Ee]|&#x?2[27]|&lt;|&gt;|&quot;|&#x?0[dDaA])`, DetXSS, "XSS: encoded characters")
	add(`(?i)(fetch\s*\(|XMLHttpRequest|ActiveXObject|WebSocket\s*\(|postMessage\s*\()`, DetXSS, "XSS: HTTP request API")
	add(`(?i)(constructor\.prototype|prototype\s*\[)`, DetXSS, "XSS: prototype manipulation")
	add(`(?i)(import\s*\(|require\s*\()`, DetXSS, "XSS: dynamic import")
	add(`(?i)(srcdoc\s*=|autofocus\s*=|accesskey\s*=|tabindex\s*=|contenteditable\s*=)`, DetXSS, "XSS: HTML attribute injection")
	add(`(?i)(xlink:href=|xlink:type=|xlink:show=|xlink:actuate=)`, DetXSS, "XSS: XLink injection")
	add(`(?i)(formaction\s*=|formmethod\s*=|formenctype\s*=|formtarget\s*=)`, DetXSS, "XSS: form attribute override")

	// Log4j / JNDI (before SSTI to avoid ${...} overlap)
	add(`(?i)(\$\{jndi:|class\.module\.classLoader|\$\{lower:jndi|\$\{upper:jndi|\$\{::-j|\$\{env:|\$\{sys:|\$\{log4j:|\$\{ctx:|\$\{java:|\$\{date:|\$\{docker:|\$\{k8s:|\$\{spring:|\$\{main:|\$\{bundle:|\$\{map:|\$\{mdc:|\$\{name:|\$\{marker:|\$\{exception:)`, DetLog4j, "Log4j: JNDI lookup")
	add(`(?i)(jndi:ldap://|jndi:rmi://|jndi:ldaps://|jndi:dns://|jndi:iiop://|jndi:http://|jndi:https://)`, DetLog4j, "Log4j: JNDI protocol")
	add(`(?i)(\$\{[^}]*:[^}]*:[^}]*\}|\$\{[^}]*24[^}]*\|%24\{|%2524\{)`, DetLog4j, "Log4j: encoded lookup")

	// SSRF (before SSTI to avoid ${...} overlap)
	add(`(?i)(169\.254\.169\.254|metadata\.google\.internal|metadata\.compute\.internal|metadata\.goog|100\.100\.100\.200|168\.63\.129\.16|fd00:ec2::23)`, DetSSRF, "SSRF: cloud metadata endpoint")
	add(`(?i)(0x7f000001|0x7f\.0\.0\.1|2130706433|017700000001|0o17700000001)`, DetSSRF, "SSRF: loopback IP variants")
	add(`(?i)(\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\blocalhost\b)`, DetSSRF, "SSRF: loopback/localhost")
	add(`(?i)(\[::1\]|\[0:0:0:0:0:0:0:1\]|\[0::1\]|\[0000:0000:0000:0000:0000:0000:0000:0001\]|\b::1\b)`, DetSSRF, "SSRF: loopback IPv6")
	add(`(?i)(gopher://|dict://|ftp://|tftp://|ldap://|ldaps://|redis://|mysql://|postgres://|ssh://|smb://|sftp://)`, DetSSRF, "SSRF: protocol smuggling")
	add(`(?i)(\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b)`, DetSSRF, "SSRF: private IP probe")
	add(`(?i)(metadata|instance-data|latest/meta-data|latest/user-data|computeMetadata|dynamic/instance-identity)`, DetSSRF, "SSRF: cloud metadata path")

	// SSTI (after Log4j/SSRF to avoid pattern overlap)
	add(`(?i)(\{\{7\*7\}\}|\$\{7\*7\}|${{7*7}}|#\{7\*7\})`, DetSSTI, "SSTI: arithmetic probe")
	add(`(?i)(__class__|__mro__|__subclasses__|__globals__|__builtins__|__init__|__dict__|__bases__|__import__)`, DetSSTI, "SSTI: Python MRO exploit")
	add(`(?i)(freemarker|nunjucks|range\.constructor|lipsum|cycler|joiner|namespace)`, DetSSTI, "SSTI: template engine globals")
	add(`(?i)(os\.popen|os\.system|subprocess\.|subprocess\.Popen|os\.environ|os\.getenv)`, DetSSTI, "SSTI: OS command access")
	add(`(?i)(class\.getResource|java\.lang|Runtime\.getRuntime|ProcessBuilder|javax\.script|org\.apache\.velocity)`, DetSSTI, "SSTI: Java class access")
	add(`(?i)(<#assign\s|<#\w+\s|__\$\{.*\}__|<%=.*%>)`, DetSSTI, "SSTI: FreeMarker/ERB/Thymeleaf probe")

	// RCE
	add(`(?i)(/bin/sh|/bin/bash|/bin/zsh|/bin/dash|/bin/ksh|/bin/csh|/bin/tcsh|/bin/fish)`, DetRCE, "RCE: shell path")
	add(`(?i)(whoami$|whoami\s|id\s*;|\bid\s+\||whoami\s*;|whoami\s+\||pwd\s*;|\bcat\s+/etc\b)`, DetRCE, "RCE: basic recon command")
	add(`(?i)(/dev/tcp/|/dev/udp/|bash\s+-i|sh\s+-i|/tmp/rev|nc\s+-e|socat\s+|ncat\s+)`, DetRCE, "RCE: reverse shell connection")
	add(`(?i)(curl\s+|wget\s+|fetch\s+|axel\s+|aria2c\s+)`, DetRCE, "RCE: download tool")
	add(`(?i)(powershell|pwsh|cmd\.exe|cmd\.com|%COMSPEC%)`, DetRCE, "RCE: Windows shell")
	add(`(?i)(certutil\s+-urlcache|bitsadmin\s+/transfer|mshta\s+|rundll32\s+|regsvr32\s+/[su])`, DetRCE, "RCE: LOLBin download")
	add(`(?i)(eval\s*\(|system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\(|popen\s*\(|proc_open\s*\(|proc_close\s*\(|assert\s*\(|create_function\s*\(|call_user_func\s*\()`, DetRCE, "RCE: PHP function")
	add(`(?i)(phpinfo\s*\(|ini_set\s*\(|ini_alter\s*\(|set_time_limit\s*\(|ignore_user_abort\s*\()`, DetRCE, "RCE: PHP config manipulation")
	add(`(?i)(include\s*\(|require\s*\(|include_once\s*\(|require_once\s*\(|allow_url_include|auto_prepend_file|auto_append_file)`, DetRCE, "RCE: PHP file inclusion")
	add(`(?i)(wmic\s+|ipconfig|systeminfo|tasklist|schtasks\s+|vssadmin\s+|net\s+(user|group|localgroup|view|share|use)\s+|net1\s+(user|group))`, DetRCE, "RCE: Windows recon")
	add(`(?i)(python\s+-c|python3\s+-c|perl\s+-[eE]|ruby\s+-e|php\s+-r|node\s+-e|java\s+-jar|javaw\s+-jar)`, DetRCE, "RCE: code execution interpreter")
	add(`(?i)(mail\s*\(|mb_send_mail\s*\(|imap_open\s*\()`, DetRCE, "RCE: PHP mail injection")
	add(`(?i)(preg_replace\s*\(.*\/[eie]|mb_ereg_replace\s*\(.*\/[eie]|preg_filter\s*\(.*\/[eie])`, DetRCE, "RCE: regex eval modifier")
	add(`(?i)(O:\d+:.*:\d+:\{|C:\d+:.*:\d+:\{|__destruct|__wakeup|__toString|__call|__callStatic|__get|__set|__invoke|__sleep|__isset|__unset)`, DetRCE, "RCE: deserialization gadget")
	add(`(?i)(rO0AB|_\$\$ND_FUNC\$\$_)`, DetRCE, "RCE: serialized object fingerprint (Java/Node)")
	add(`(?i)(java\.lang\.Runtime|java\.lang\.ProcessBuilder|Runtime\.getRuntime|AccessController\.doPrivileged|Unsafe\.defineClass|URLClassLoader\.newInstance)`, DetRCE, "RCE: Java runtime access")
	add(`(?i)(\$\{.{0,200}?\}\s*\(|`+"`"+`\w+\s+`+"`"+`|\$\(.{0,200}?\)|;.{0,100}?\b(bash|sh|python|perl|ruby|php|node)\s)`, DetRCE, "RCE: command substitution")
	add(`(?i)(cmd\.exe\s+[/\/][ck]|command\s*=\s*cmd|exec\s*=\s*cmd|wscript\.exe|cscript\.exe)`, DetRCE, "RCE: Windows command execution")

	// XXE / XML Injection (before path traversal to catch SYSTEM file references)
	add(`(?i)(<!DOCTYPE|<!ENTITY|<!ELEMENT|<!ATTLIST|<!NOTATION|%xxe|&xxe|<!\[%xxe)`, DetXXE, "XXE: entity declaration")
	add(`(?i)(<!DOCTYPE\s+\w+\s+(SYSTEM|PUBLIC)\s+")`, DetXXE, "XXE: external DTD")
	add(`(?i)(<!ENTITY\s+\w+\s+(SYSTEM|PUBLIC)\s+")`, DetXXE, "XXE: external entity")
	add(`(?i)(ENTITY\s+%\s+\w+\s+SYSTEM|<!ENTITY\s+%\s+\w+\s+")`, DetXXE, "XXE: parameter entity")
	add(`(?i)(/xinclude|xmlns:xi=|xi:include|xi:fallback|xpointer)`, DetXXE, "XXE: XInclude attack")
	add(`(?i)(<!DOCTYPE\s+[a-zA-Z].{0,300}?\[.{0,300}?<!ENTITY)`, DetXXE, "XXE: internal DTD entity")

	// Path Traversal / LFI
	add(`(?i)(\.\./|\.\.\\|\.\.%2[fF]|\.\.%5[cC]|%2e%2e%2[fF]|%2e%2e%5[cC])`, DetPathTraversal, "LFI: directory traversal")
	add(`(?i)(\.\.%00|%00\.\.|\.\.\\x00|\\x00\.\.|\.\.%2500|\.\.\\0)`, DetPathTraversal, "LFI: null byte injection")
	add(`(?i)(/etc/passwd|/etc/shadow|/etc/hosts|/etc/issue|/etc/group|/etc/fstab|/etc/crontab|/etc/mtab|/etc/resolv\.conf|/etc/hostname|/etc/hosts\.allow|/etc/hosts\.deny|/etc/ssh/sshd_config|/etc/ssh/ssh_config|/etc/ssl/certs)`, DetPathTraversal, "LFI: Unix system files")
	add(`(?i)(/proc/self|/proc/1/|/proc/self/environ|/proc/self/fd|/proc/self/cmdline|/proc/self/maps|/proc/self/mem|/proc/self/root|/proc/self/cwd|/proc/net/|/proc/version|/proc/cpuinfo|/proc/meminfo|/proc/diskstats|/proc/modules|/proc/mounts|/proc/cmdline)`, DetPathTraversal, "LFI: /proc filesystem probe")
	add(`(?i)(/windows/win\.ini|/windows/system32/|/windows/system|/windows/system|/windows/temp/|/boot\.ini|/autoexec\.bat|/windows/repair|/windows/regedit\.exe|/windows/explorer\.exe|/windows/notepad\.exe|/winnt/|pagefile\.sys|ntldr|NTDETECT\.COM|boot\.ini)`, DetPathTraversal, "LFI: Windows system files")
	add(`(?i)(/\.ssh/|/\.git/)`, DetPathTraversal, "LFI: dotfile access")
	add(`(?i)(/root/|/home/|/Users/)[^?]*/(\.ssh/|\.bash_history|\.bashrc|\.profile|\.zshrc|\.config|\.local|\.cache)`, DetPathTraversal, "LFI: user home data")
	add(`(?i)(/var/log/|/var/mail/|/var/spool/|/var/backups/|/var/www/|/var/www/html/|/var/www/cgi-bin/|/usr/local/etc/|/usr/local/bin/)`, DetPathTraversal, "LFI: var/usr files")
	add(`(?i)(\.[\w-]+\.\w+://|\.\w+:\/\/)`, DetPathTraversal, "LFI: wrapper chain")

	// LFI Wrapper Abuse
	add(`(?i)(phar://|zip://|rar://|bz2://|zlib://|data://text/plain|data://text/html|data://text/javascript|data://application|expect://|php://input|php://filter|php://temp|php://memory|php://stdin|php://stdout|php://output|compress\.zlib|compress\.bzip2|compress\.lzf)`, DetLFIWrapper, "LFI: PHP stream wrapper")
	add(`(?i)(convert\.base64-encode|convert\.iconv|resource=.*\.php|read=convert\.base64)`, DetLFIWrapper, "LFI: filter chain wrapper")

	// GraphQL Introspection
	add(`(?i)(__schema|__type|__typename|__field|__directive|__enumValue|__InputValue|IntrospectionQuery|type\s*\{[^}]*\})`, DetGraphQL, "GraphQL: introspection query")
	add(`(?i)({__schema|{__type|{__typename)`, DetGraphQL, "GraphQL: schema discovery")
	add(`(?i)(query\s*\{[^}]*\{[^}]*\}|mutation\s*\{[^}]*\{|subscription\s*\{)`, DetGraphQL, "GraphQL: operation discovery")

	// WordPress Probe (before sensitive file to catch wp paths first)
	add(`(?i)(/wp-content/plugins/|/wp-content/themes/|/wp-content/uploads/|/wp-content/languages/|/wp-content/cache/|/wp-content/upgrade/|/wp-content/index\.php)`, DetWPProbe, "WordPress: content directory probe")
	add(`(?i)(/wp-json/wp/v2/|/wp-json/oembed/|/wp-json/|/index\.php/rest_route)`, DetWPProbe, "WordPress: REST API probe")
	add(`(?i)(/wp-includes/|/wp-admin/js/|/wp-admin/css/|/wp-admin/images/)`, DetWPProbe, "WordPress: core directory probe")
	add(`(?i)(/xmlrpc\.php|/xmlrpc\.php\?rsd)`, DetWPProbe, "WordPress: XML-RPC probe")
	add(`(?i)(/wp-cron\.php|/wp-activate\.php|/wp-signup\.php|/wp-trackback\.php|/wp-mail\.php|/wp-links-opml\.php)`, DetWPProbe, "WordPress: misc endpoint probe")
	add(`(?i)(/wp-content/plugins/woocommerce|/wp-content/plugins/elementor|/wp-content/plugins/contact-form-7|/wp-content/plugins/wordfence|/wp-content/plugins/akismet|/wp-content/plugins/yoast|/wp-content/plugins/jetpack|/wp-content/plugins/redirection|/wp-content/plugins/tablepress|/wp-content/plugins/nextend|/wp-content/plugins/gravityforms)`, DetWPProbe, "WordPress: popular plugin probe")
	add(`(?i)(/wp-content/upgrade/|/wp-content/backup-|/wp-content/ai1wm-backups|/wp-content/snapshots)`, DetWPProbe, "WordPress: backup directory probe")
	add(`(?i)(/wp-content/debug\.log|/wp-content/error\.log|/wp-content/install\.php|/wp-content/setup\.php)`, DetWPProbe, "WordPress: sensitive file probe")

	// Sensitive File Probe
	add(`(?i)(\.env|\.env\.local|\.env\.prod|\.env\.dev|\.env\.stage|\.env\.example)`, DetSensitiveFile, "Sensitive: environment file")
	add(`(?i)(\.git/config|\.git/HEAD|\.git/index|\.git/objects|\.git/refs|\.gitignore|\.gitattributes|\.gitmodules)`, DetSensitiveFile, "Sensitive: git file")
	add(`(?i)(wp-config\.php|wp-config\.txt|wp-config\.bak|wp-config\.old|wp-config\.inc)`, DetSensitiveFile, "Sensitive: WordPress config")
	add(`(?i)(id_rsa|id_rsa\.pub|id_dsa|id_ecdsa|id_ed25519|authorized_keys|known_hosts|\.ssh/)`, DetSensitiveFile, "Sensitive: SSH key")
	add(`(?i)(\.aws/credentials|\.aws/config|\.azure/credentials|\.azure/config|\.gcp/credentials|\.gcp/config|credentials\.json|service-account\.json|application_default_credentials\.json)`, DetSensitiveFile, "Sensitive: cloud credential file")
	add(`(?i)(\.htaccess|\.htpasswd|\.htgroup)`, DetSensitiveFile, "Sensitive: htaccess file")
	add(`(?i)(docker-compose\.yml|docker-compose\.override\.yml|Dockerfile|docker\.env)`, DetSensitiveFile, "Sensitive: Docker config")
	add(`(?i)(composer\.json|composer\.lock|package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|go\.mod|go\.sum|Cargo\.toml|Cargo\.lock|Gemfile|Gemfile\.lock|Pipfile|Pipfile\.lock|setup\.py|requirements\.txt)`, DetSensitiveFile, "Sensitive: dependency file")
	add(`(?i)(\.npmrc|\.yarnrc|\.gemrc|\.pypirc|\.pypi\.json|netrc|\.netrc|_netrc)`, DetSensitiveFile, "Sensitive: package manager config")
	add(`(?i)(config\.php|config\.inc\.php|database\.php|db\.config|db\.php|connection\.php|settings\.php|settings\.json|app\.config|app\.conf|web\.config|application\.config)`, DetSensitiveFile, "Sensitive: app config file")
	add(`(?i)(dump\.sql|backup\.sql|db\.sql|database\.sql|export\.sql|mysqldump|pgdump|db_backup|\.ibd|\.frm|\.myd|\.myi|\.sqlite|\.sqlite3|\.db)`, DetSensitiveFile, "Sensitive: database export")
	add(`(?i)(\.bak|\.backup|\.~bk|\.sav|\.save|\.old|\.orig|\.sw[op]|\.copy|\.tmp|\.temp|\.dump|\.dump\.gz|\.backup\.gz|\.tar\.gz|\.zip|\.rar)`, DetSensitiveFile, "Sensitive: backup file")
	add(`(?i)(/var/log/|access\.log|error\.log|debug\.log|app\.log|laravel\.log|wp-content/debug\.log)`, DetSensitiveFile, "Sensitive: log file")
	add(`(?i)(\.pem|\.key|\.crt|\.cert|\.p12|\.pfx|\.jks|\.keystore|\.truststore|ca-certificates)`, DetSensitiveFile, "Sensitive: certificate/key file")
	add(`(?i)(wp_filemanager\.php|wp-file-manager|elfinder|ckfinder|uploader\.php)`, DetSensitiveFile, "Sensitive: file manager probe")
	add(`(?i)(phpinfo\.php|phpinfo\.txt|info\.php|test\.php|debug\.php|php\.php|info\.asp|info\.jsp|test\.asp|test\.jsp)`, DetSensitiveFile, "Sensitive: info page probe")
	add(`(?i)(\.gitignore|\.dockerignore|\.editorconfig|\.prettierrc|\.eslintrc|\.jshintrc|\.stylelintrc|browserslist|postcss\.config|webpack\.config|vite\.config|rollup\.config)`, DetSensitiveFile, "Sensitive: dev config file")

	// Admin Interface Probe
	add(`(?i)(/phpmyadmin|/pma|/mysql/admin|/adminer|/phppgadmin|/pgadmin|/admin/mysql)`, DetAdminProbe, "Admin: database interface")
	add(`(?i)(/actuator/|/actuator/env|/actuator/health|/actuator/info|/actuator/metrics|/actuator/dump|/actuator/heapdump|/actuator/threaddump|/actuator/logfile|/actuator/shutdown|/actuator/configprops|/actuator/beans|/actuator/mappings|/actuator/conditions)`, DetAdminProbe, "Admin: Spring Boot actuator")
	add(`(?i)(/console/|/h2-console|/h2/|/h2-console\.do|/h2-console\.action)`, DetAdminProbe, "Admin: H2 database console")
	add(`(?i)(/heapdump|/heap\.dmp|/dump\.bin|/dumptofile|/jvm\.dump)`, DetAdminProbe, "Admin: heap dump access")
	add(`(?i)(/jolokia|/jolokia/|/actuator/jolokia|/jmx|/jmx-console|/jmxinvoke)`, DetAdminProbe, "Admin: JMX/jolokia endpoint")
	add(`(?i)(/admin|/admin/|/administrator|/adm/|/panel/|/cpanel/|/dashboard/|/manage/|/management/|/manager/|/backend/|/backoffice/)`, DetAdminProbe, "Admin: admin panel")
	add(`(?i)(/swagger|/swagger-ui|/swagger-resources|/api-docs|/v2/api-docs|/v3/api-docs|/openapi\.json|/swagger\.json)`, DetAdminProbe, "Admin: API documentation")
	add(`(?i)(/solr/|/elasticsearch/|/zabbix/|/grafana/|/prometheus/|/kibana/|/nagios/|/cacti/|/munin/|/monitoring/)`, DetAdminProbe, "Admin: monitoring tool")
	add(`(?i)(/wp-login\.php|/wp-admin/|/wp-admin/admin-ajax\.php|/administrator/)`, DetAdminProbe, "Admin: WordPress admin")
	add(`(?i)(/\.svn/|/\.svn/entries|/\.svn/wc\.db|/\.DS_Store|/Thumbs\.db|/\.hg/|/\.bzr/|/WEB-INF/|/WEB-INF/web\.xml|/WEB-INF/database\.properties)`, DetAdminProbe, "Admin: VCS / metadata")
	add(`(?i)(/debug/|/api/debug|/api/v1/debug|/debug\.php|/dev/|/api/dev|/test/|/testing/|/staging/)`, DetAdminProbe, "Admin: debug/dev endpoint")
	add(`(?i)(/cgi-bin/phpinfo|/cgi-bin/php|/aws-tools/|/server-info|/server-status|/info\.aspx|/trace\.axd|/elb-status)`, DetAdminProbe, "Admin: server info page")
	add(`(?i)(/\.aws/|/\.azure/|/\.gcp/|/credentials|/secrets|/tokens|/keys|/passwords)`, DetAdminProbe, "Admin: credential path")

	// CGI Probe
	add(`(?i)(/cgi-bin/|/cgi-bin/test.cgi|/cgi-sys/|/fcgi-bin/|/CGI-BIN/)`, DetCGIProbe, "CGI: cgi-bin probe")
	add(`(?i)(\.cgi|\.pl|\.fcgi|\.py|\.rb)`, DetCGIProbe, "CGI: script extension probe")

	// Open Redirect
	add(`(?i)([\?&](url|redirect|next|return|ret|to|target|redirect_uri|continue|destination|callback|ref|link|path)=https?://)`, DetOpenRedirect, "Open redirect: URL parameter")
	add(`(?i)([\?&](url|redirect|next|return|ret|to|target|redirect_uri|continue|destination|callback|ref|link|path)=//)`, DetOpenRedirect, "Open redirect: protocol-relative parameter")
	add(`(?i)([\?&](url|redirect|next|return|ret|to|target|redirect_uri|continue|destination|callback|ref|link|path)=/\\)`, DetOpenRedirect, "Open redirect: backslash bypass")

	// LDAP Injection
	add(`(?i)(\(&\(|\(\|\(|\)\|\(|\)&\(|\(uid=\*|\(cn=\*|\(samaccountname=\*|\(userAccountControl=|\(objectClass=|\(objectCategory=)`, DetLDAPInjection, "LDAP: filter injection")
	add(`(?i)(%28%26%28|%28%7c%28|%29%7c%28|%29%26%28|%2a%29%28|%29%28%7c)`, DetLDAPInjection, "LDAP: URL-encoded filter injection")

	// XPath Injection
	add(`(?i)('(\s*or\s*)'1'='1|"(\s*or\s*)"1"="1)`, DetXPathInjection, "XPath: tautology injection")
	add(`(?i)(\]\|\s*//\s*\*|\.//\s*\*)`, DetXPathInjection, "XPath: path manipulation")

	// CRLF / Log Injection
	add(`(?i)(%0[dD]%0[aA].{0,50}?[a-zA-Z-]+:|%0d%0a%0d%0a|%0d%0aContent-Length|%0d%0aLocation|%0d%0aSet-Cookie|%0d%0aWWW-Authenticate|%0d%0aHost:)`, DetCRLFInjection, "CRLF: HTTP header injection")
	add(`(?i)(\r\n\s*[a-zA-Z-]+:|\r\n\r\n)`, DetCRLFInjection, "CRLF: literal header injection")

	// Prototype Pollution
	add(`(?i)(__proto__|constructor\.prototype|\[constructor\]\.prototype)`, DetProtoPollution, "Prototype pollution: __proto__ access")
	add(`(?i)(\"__proto__\"\s*:|\'__proto__\'\s*:|\"constructor\"\s*:\s*\{\s*\"prototype\")`, DetProtoPollution, "Prototype pollution: JSON payload")

	// SSI Injection
	add(`(?i)(<!--#include\s+|<!--#exec\s+|<!--#echo\s+|<!--#set\s+|<!--#printenv\s+|<!--#config\s+|<!--#flastmod\s+|<!--#fsize\s+)`, DetSSIInjection, "SSI: server-side include directive")
	add(`(?i)(<!--#exec\s+cmd=|<!--#exec\s+cgi=|<!--#include\s+virtual=|<!--#include\s+file=)`, DetSSIInjection, "SSI: exec/include attempt")
	add(`(?i)(#exec\s+cmd=|#exec\s+cgi=|#include\s+virtual=|#include\s+file=|#echo\s+var=)`, DetSSIInjection, "SSI: short-form directive")

	// Scanner tools
	scannerUAs := []string{
		"sqlmap", "nikto", "dirbuster", "gobuster", "wfuzz", "nmap",
		"zap", "burpsuite", "burp suite", "acunetix", "netsparker", "arachni",
		"masscan", "hydra", "medusa", "openvas", "nessus", "snort",
		"python-requests", "python-urllib", "python3-requests",
		"python3-urllib", "go-http-client", "Go-http-client",
		"curl", "wget", "libwww-perl", "scrapy", "aiohttp",
		"httpx", "nuclei", "ffuf", "katana", "jaeles", "arjun",
		"dalfox", "xsstrike", "commix", "tplmap", "nosqlmap",
		"whatweb", "wpscan", "joomscan", "droopescan",
		"qualys", "nexpose",
		"crackmapexec", "cme", "responder", "bettercap",
		"golismero", "wapiti", "skipfish", "uniscan", "webscarab",
		"paros", "vega", "appscan", "probely", "crashtest",
		"metasploit", "beef", "maltego", "shodan", "censys",
		"zgrab", "zmap", "massdns", "dnsx", "subfinder",
		"assetfinder", "amass", "waybackurls",
		"gau", "httprobe", "tlsx", "rustscan",
		"naabu", "maigret", "sherlock", "holehe", "socialscan",
	}
	scannerPat := "(?i)(" + strings.Join(scannerUAs, "|") + ")"
	add(scannerPat, DetScanner, "Scanner / automated tool detected")

	return p
}

var rawPatterns []struct {
	re    *regexp.Regexp
	dtype DetectionType
	desc  string
}

func init() {
	addRaw := func(pattern string, dtype DetectionType, desc string) {
		rawPatterns = append(rawPatterns, struct {
			re    *regexp.Regexp
			dtype DetectionType
			desc  string
		}{regexp.MustCompile(pattern), dtype, desc})
	}

	addRaw(`(?i)(%2e%2e%2f|%2e%2e/|\.%2e/|%2e\.%2f|%252e%252e%252f|\.\.%252f|.%2e%2e%2f|%c0%ae%c0%ae%c0%af|%c0%ae%c0%ae/|%252e%252e%252f|..%c0%af|%c0%ae%c0%ae)`, DetPathTraversal, "LFI: encoded path traversal (raw URI)")
	addRaw(`(?i)(127\.0\.0\.1|localhost|0x7f000001|2130706433)(:|%3a|%3A)`, DetSSRF, "SSRF: internal host probe (raw URI)")
	addRaw(`(?i)(%22|%27|%3c|%3e|%3C|%3E|%00|null|undefined|NaN)`, DetXSS, "XSS: raw encoded payload")
	addRaw(`(?i)(%2524{|%2525|%252e%252e%252f|%252f..|..%252f|%252f)`, DetPathTraversal, "LFI: double-encoded traversal (raw URI)")
	addRaw(`(?i)(\.\w+://\w+\.\w+|\.\w+://\d+\.\d+\.\d+\.\d+)`, DetSSRF, "SSRF: protocol wrapper (raw URI)")
	addRaw(`(?i)(\$%7bjndi|\$%7b.{0,100}?jndi|\$%7blower:jndi|\$%7bupper:jndi)`, DetLog4j, "Log4j: URL-encoded JNDI (raw URI)")
	addRaw(`(?i)(%00|%0d|%0a|%0D|%0A|%09)`, DetCRLFInjection, "CRLF: encoded control char (raw URI)")
	addRaw(`(?i)(%E5%98%8A|%E5%98%8D)`, DetCRLFInjection, "CRLF: Java ghost bits bypass (raw URI)")
}

func (d *Detector) Detect(entry *types.LogEntry) *Detection {
	dets := d.DetectAll(entry)
	if len(dets) > 0 {
		first := dets[0]
		return &first
	}
	return nil
}

func (d *Detector) DetectAll(entry *types.LogEntry) []Detection {
	rawURI := entry.URI
	uri := rawURI
	if unescaped, err := url.QueryUnescape(uri); err == nil {
		uri = unescaped
	}
	ua := entry.UserAgent

	stats := d.ipStats[entry.RemoteIP]
	if stats == nil {
		stats = &IPDetStats{}
		d.ipStats[entry.RemoteIP] = stats
	}
	stats.Total++

	if entry.Status == 401 || entry.Status == 403 {
		stats.AuthFailures++
	}
	if entry.Status == 404 {
		stats.NotFound++
	}

	seen := make(map[DetectionType]bool)
	var dets []Detection

	for _, p := range d.patterns {
		if seen[p.dtype] {
			continue
		}
		if p.re.MatchString(uri) || p.re.MatchString(ua) {
			seen[p.dtype] = true
			dets = append(dets, Detection{
				Type:   p.dtype,
				IP:     entry.RemoteIP,
				URI:    entry.URI,
				Status: entry.Status,
				Desc:   p.desc,
			})
		}
	}

	for _, p := range rawPatterns {
		if seen[p.dtype] {
			continue
		}
		if p.re.MatchString(rawURI) || p.re.MatchString(ua) {
			seen[p.dtype] = true
			dets = append(dets, Detection{
				Type:   p.dtype,
				IP:     entry.RemoteIP,
				URI:    entry.URI,
				Status: entry.Status,
				Desc:   p.desc,
			})
		}
	}

	return dets
}

func (d *Detector) IPStats() map[string]*IPDetStats {
	return d.ipStats
}

func (d *Detector) IsSuspicious(ip string, authThreshold, notFoundThreshold, totalThreshold int) bool {
	stats := d.ipStats[ip]
	if stats == nil {
		return false
	}
	if stats.AuthFailures >= authThreshold {
		return true
	}
	if stats.NotFound >= notFoundThreshold {
		return true
	}
	if stats.Total >= totalThreshold {
		return true
	}
	return false
}
