# ZScaler NSS Web Logs — Field Reference

Source of truth: `docs/NSS_Feed_Output_Format__Web_Logs.pdf` (39 pages, "Internet & SaaS (ZIA):
NSS Feed Output Format: Web Logs", (c) 2026 Zscaler, Inc.), read in full with the `Read` tool's
`pages` parameter. Committed here so nobody has to re-read the PDF. Every field below is the
document's own `%s{...}`/`%d{...}` token, its description, and a representative example, grouped
under the document's own section headings, in the document's own order.

Two independent tasks wrote this file — the device/asset hot-column + tag-bank work (the field
inventory and reconciliation below) and, appended in its own section near the end, a concurrent
change wiring obfuscated/Base64/hex-encoded field variants into the parser. Append, don't
overwrite, if you're adding a third.

The document's own sample line (its cover page, "View a sample web log"):

```
"Mon Jun 20 15:29:11 2022","new-gre","HTTP","ebay.com/","Blocked","Ebay","Consumer Apps","72",
"14061","0","0","Productivity Loss","Shopping and Auctions","Online Shopping","None","None","0",
"None","None","new-gre","Default Department","172.17.3.49","66.211.175.229","GET","403",
"curl/7.68.0","None","FwFilter","Firewall_1","Other","None","NA","NA","N/A"
```

This is a positional CSV export of an admin-configured field list — the `%s{...}` token is the
canonical identifier used to build that format string (and to key a key=value export), not
necessarily the literal string that appears in a CSV row. See **"Task 2 — reconciliation"** below
for what that means for this codebase's own parser.

## Date/Time

| Field | Meaning | Example |
|---|---|---|
| `%s{time}` | Time and date of the transaction, excludes time zone | `Mon Oct 16 22:55:48 2023` |
| `%s{tz}` | Time zone configured for the NSS feed | `GMT` |
| `%02d{ss}` | Seconds (0-59), derived from Logged Time | `48` |
| `%02d{mm}` | Minutes (0-59), derived | `55` |
| `%02d{hh}` | Hours (0-23), derived | `22` |
| `%02d{dd}` | Day of month (1-31), derived | `16` |
| `%02d{mth}` | Month of year, derived | `10` |
| `%04d{yyyy}` | Year, derived | `2023` |
| `%s{mon}` | Month name, derived | `Oct` |
| `%s{day}` | Day of week, derived | `Mon` |
| `%d{epochtime}` | Epoch time of the transaction | `1578128400` |

## User Information

| Field | Meaning | Example |
|---|---|---|
| `%s{login}` | User's login name, email address format | `jdoe@safemarch.com` |
| `%s{dept}` | Department of the user | `Sales` |
| `%s{company}` | Company name | `Zscaler` |
| `%s{cloudname}` | Name of the Zscaler cloud | `zscaler.net` |

## Bandwidth Control

| Field | Meaning | Example |
|---|---|---|
| `%d{txn_delay_req}` | Bandwidth transaction request delay (ms) | `1,234` |
| `%d{txn_delay_resp}` | Bandwidth transaction response delay (ms) | `1,234` |
| `%d{throttlereqsize}` | Throttled transaction size, uplink (bytes) | `5` |
| `%d{throttlerespsize}` | Throttled transaction size, downlink (bytes) | `7` |
| `%s{bwthrottle}` | Whether the transaction was throttled | `Yes` |
| `%s{bwclassname}` | Bandwidth class name | `Office Apps` |
| `%s{bwrulename}` | Bandwidth rule name | `Microsoft 365` |

## Cloud Application

| Field | Meaning | Example |
|---|---|---|
| `%s{appname}` | Cloud application name | `Dropbox` |
| `%s{appclass}` | Cloud application category | `Collaboration` |
| `%s{app_risk_score}` | Computed/assigned risk index, 1 (lowest) - 5 (highest); `None` if unavailable | `1-5` / `None` |
| `%s{app_status}` | Status of the cloud application | `Sanctioned` / `Unsanctioned` / `N/A` |
| `%s{activity}` | Action the user performed on the application | `Download` |
| `%s{prompt_req}` | The prompt entered in a generative AI application | — |
| `%s{prompt_class}` | Category assigned to the user's input prompt | — |
| `%s{inst_level1_type}` | Level 1 instance type (e.g. Organization for GCP) | `ORG` |
| `%s{inst_level1_id}` | Level 1 instance id | `12324321232` |
| `%s{inst_level1_name}` | Level 1 instance name, if available | `org_12324321232` |
| `%s{inst_level2_type}` | Level 2 instance type (e.g. Project for GCP) | `PROJECT` |
| `%s{inst_level2_id}` | Level 2 instance id | `project_max1` |
| `%s{inst_level2_name}` | Level 2 instance name, if available | `genai_pr` |
| `%s{inst_level3_type}` | Level 3 instance type (e.g. Resource Type for GCP) | `RESOURCE_TYPE` |
| `%s{inst_level3_id}` | Level 3 instance id | `Vertex AI` |
| `%s{inst_level3_name}` | Level 3 instance name, if available | `None` |

## Data Center

| Field | Meaning | Example |
|---|---|---|
| `%s{datacenter}` | Name of the data center | `CA Client Node DC` |
| `%s{datacentercity}` | City where the data center is located | `Sa` |
| `%s{datacentercountry}` | Country where the data center is located | `US` |

## Data Loss Prevention (DLP)

| Field | Meaning | Example |
|---|---|---|
| `%s{dlpdict}` | DLP dictionaries matched, if any | `Credit Cards\|Gambling\|MRN Numbers` |
| `%s{dlpdicthitcount}` | Number of hits per matched dictionary | `4\|5\|1\|2` |
| `%s{dlpeng}` | DLP engine matched, if any | `HIPAA` |
| `%d{dlpidentifier}` | Unique DLP identifier; not populated if `exempt_dlpidentifier` is | `6646484838839025669` |
| `%d{exempt_dlpidentifier}` | Unique DLP identifier for a scan that timed out (exempted); not populated if `dlpidentifier` is | `5526484838837385671` |
| `%s{dlpmd5}` | MD5 hash of the transaction | `154f149b1443fbfa8c121d13e5c019a1` |
| `%s{dlprulename}` | DLP rule applied — Allow rules only | `DLP_Rule_1` |
| `%s{trig_dlprulename}` | DLP rule that triggered (allowed or blocked) | `DLP_Rule_1` |
| `%s{other_dlprulenames}` | DLP rules evaluated and passed, no action taken | `[DLP_Rule_4, DLP_Rule_5]` |
| `%s{all_dlprulenames}` | All DLP rules whether triggered or not | `[DLP_Rule_1, DLP_Rule_4, DLP_Rule_5]` |
| `%s{dlp_policy_action}` | DLP policy action taken | `Incident Reported` |
| `%s{dlp_confirm_justification_msg}` | Message a user entered to justify a Confirm-action DLP rule | `My manager approved it` |

## Extranet Application

| Field | Meaning | Example |
|---|---|---|
| `%s{extranet_name}` | Name of the extranet resource associated with the transaction | `Extranet 123` |

## File Type Control

| Field | Meaning | Example |
|---|---|---|
| `%s{ft_rulename}` | File Type Control rule applied — Allow rules only | `File_Type_1` |
| `%s{fileclass}` | Class of file downloaded | `Active Web Contents` |
| `%s{filetype}` | Type of file downloaded | `RAR Files` |
| `%s{filename}` | Name of downloaded file | `nssfeed.txt` |
| `%s{filesubtype}` | Subtype (extension) of the downloaded file | `rar` |
| `%s{upload_fileclass}` | Class of file uploaded | `Archive Files` |
| `%s{upload_filetype}` | Type of file uploaded | `Windows Executables` |
| `%s{upload_filename}` | Name of uploaded file | `nssfeed.exe` |
| `%s{upload_filesubtype}` | Subtype (extension) of the uploaded file | `exe` |
| `%s{upload_doctypename}` | Document type uploaded/downloaded | `Corporate Finance` |
| `%s{upload_doc_sub_type}` | Document subtype | `Income Statements` |
| `%s{unscannabletype}` | Unscannable file type | `Encrypted File` |

## Forwarding Control

| Field | Meaning | Example |
|---|---|---|
| `%s{rdr_rulename}` | Redirect/forwarding policy rule name | `FWD_Rule_1` |
| `%s{fwd_type}` | Forwarding method used | `Direct` / `Drop` / `Proxy Chaining` / `ZPA` |
| `%s{fwd_gw_name}` | Forwarding gateway name | `FWD_1` |
| `%s{fwd_gw_ip}` | Forwarding gateway IP | `10.1.1.1` |
| `%s{zpa_app_seg_name}` | ZPA application segment name | `ZPA_test_app_segment` |

## HTTP Transaction

| Field | Meaning | Example |
|---|---|---|
| `%d{reqdatasize}` | HTTP request payload size, excludes headers (bytes) | `1000` |
| `%d{reqhdrsize}` | HTTP request header size (bytes) | `300` |
| `%d{reqsize}` | Request size (bytes) | `1300` |
| `%d{respdatasize}` | HTTP response payload size, excludes headers (bytes) | `10000` |
| `%d{resphdrsize}` | HTTP response header size (bytes) | `500` |
| `%d{respsize}` | Total HTTP response size, header + payload (bytes) | `10500` |
| `%d{totalsize}` | Total transaction size, request + response (bytes) | `11800` |
| `%s{reqmethod}` | HTTP request method | `invalid, get, connect` |
| `%s{reqversion}` | HTTP request version | `1.1` |
| `%s{respcode}` | HTTP response code sent to the client | `403-Forbidden` |
| `%s{respversion}` | HTTP response version | `1.0` |
| `%s{referer}` | HTTP referrer URL | `www.google.com` |
| `%s{refererhost}` | Hostname of the referrer URL | `www.example.com` |
| `%s{uaclass}` | User agent class | `Firefox, Chrome, Safari` |
| `%s{ua}` | Full user agent string | `Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0)` |
| `%s{ua_token}` | User agent token; `None` if it doesn't exist | `Google Chrome (0.x)` |
| `%s{host}` | Destination hostname (request-line host, falls back to Host header) | `mail.google.com` |
| `%s{url}` | Destination URL, excludes the protocol identifier | `www.trythisencodeurl.com/index` |
| `%s{df_hostname}` | TLS SNI when it mismatches the HTTPS host header (domain fronting) | — |
| `%s{df_hosthead}` | HTTP/S transactions with a domain-fronting FQDN mismatch | — |
| `%s{contenttype}` | Content type name | `image/gif` |

## Mobile Application

| Field | Meaning | Example |
|---|---|---|
| `%s{mobappname}` | Name of the mobile app, if any | `Adobe Reader, Amazon, Dropbox` |
| `%s{mobappcat}` | Category of the mobile app, if any | `Communication, Education, Games` |
| `%s{mobdevtype}` | Type of mobile device | `iOS, Google Android, Apple iPhone` |

## Network

| Field | Meaning | Example |
|---|---|---|
| `%s{cip}` | Client IP (internal if visible, e.g. GRE tunnel/XFF; otherwise same as `cintip`) | `192.168.2.200` |
| `%s{cintip}` | Client internet (NATed public) IP; same as `cip` if internal IP isn't visible | `203.0.113.5` |
| `%s{cpubip}` | Client public IP | `198.51.100.100` |
| `%d{clt_sport}` | Client source port | `12345` |
| `%s{srcip_country}` | Country associated with the source IP | `Afghanistan` |
| `%s{dstip_country}` | Country associated with the destination IP | `Portugal` |
| `%s{is_src_cntry_risky}` | Whether the source IP's country is risky | `Yes` |
| `%s{is_dst_cntry_risky}` | Whether the destination IP's country is risky | `No` |
| `%s{sip}` | Destination server IP; `0.0.0.0` if the request was blocked | `1.1.1.1` |
| `%d{srv_dport}` | Server destination port | `443` |
| `%s{proto}` | Protocol type of the transaction | `HTTP, FTP` |
| `%s{alpnprotocol}` | ALPN protocol | `FTP, SMB` |
| `%s{trafficredirectmethod}` | Traffic forwarding method to Public Service Edges for ZIA | `DNAT, GRE, IPSEC, PBF, PAC, PAC_GRE, PAC_IPSEC, Zscaler Client Connector` |
| `%s{location}` | Gateway location/sub-location of the source | `Headquarters` |
| `%s{userlocationname}` | Actual traffic origination point (Zero Trust Browser); `None` if not applicable | — |

## Policy

| Field | Meaning | Example |
|---|---|---|
| `%s{ruletype}` | Type of policy — Block rules only | `File Type Control, Data Loss Prevention, Sandbox` |
| `%s{rulelabel}` | Rule name applied — Block rules only | `URL_Filtering_1` |
| `%s{action}` | Action the service took on the transaction | `Allowed, Blocked` |
| `%s{reason}` | Action + policy applied, if blocked | `Virus/Spyware/Malware Blocked`, `Not allowed to browse this category` |
| `%s{urlfilterrulelabel}` | Rule name applied to the URL filter | `URL_Filtering_1` |
| `%s{apprulelabel}` | Rule name applied to the cloud application | `File_Sharing_1` |

## Sandbox

| Field | Meaning | Example |
|---|---|---|
| `%s{bamd5}` | MD5 of the detected malware file, or the file sent for Sandbox analysis | `196a3d797bfee07fe4596b69f4ce1141` |
| `%s{sha256}` | SHA-256 of identical files | `81ec78bc8298568bb5ea66d3c2972b670d0f7459b6cdbbcaacce90ab417ab15c` |

## SSL/TLS

| Field | Meaning | Example |
|---|---|---|
| `%s{ssldecrypted}` | Whether the transaction was SSL/TLS inspected | `Yes / No` |
| `%s{ssl_rulename}` | SSL/TLS Inspection policy rule applied | `SSL/TLS_Rule_1` |
| `%s{externalspr}` | SSL/TLS policy reason | `Blocked, Inspected, N/A, Not inspected because of ...` |
| `%s{keyprotectiontype}` | HSM or software protection intermediate CA used for SSL/TLS interception | `HSM Protection` |
| `%s{ja4_str}` | JA4 network fingerprint for the SSL/TLS connection | `t13d191000_9dc949149365_e7c285222651` |

## Client Connection

| Field | Meaning | Example |
|---|---|---|
| `%s{clientsslcipher}` | Negotiated cipher suite, client<->Zscaler | `SSL3_CK_RSA_NULL_MD5` |
| `%s{clienttlsversion}` | TLS version, client<->Zscaler | `SSL2, SSL3, TLS1_1, TLS1_2, TLS1_3` |
| `%s{clientsslsessreuse}` | Client cipher reuse information | `Unknown, No, Yes` |
| `%s{cltsslfailreason}` | Reason for the client SSL/TLS handshake failure | `Bad Record Mac, Certificate Unknown, Close Notify` |
| `%d{cltsslfailcount}` | Number of failed client SSL/TLS handshake attempts | — |
| `%d{client_tls_keyex_pqc_offers}` | Whether the client offered a post-quantum key exchange algorithm | `0 or 1` |
| `%d{client_tls_keyex_non_pqc_offers}` | Whether the client offered a non-PQC key exchange algorithm | `0 or 1` |
| `%d{client_tls_keyex_hybrid_offers}` | Whether the client offered a hybrid key exchange algorithm | `0 or 1` |
| `%d{client_tls_keyex_unknown_offers}` | Whether the client offered an unknown key exchange algorithm | `0 or 1` |
| `%d{client_tls_sig_pqc_offers}` | Whether the client offered a PQC digital signature algorithm | `0 or 1` |
| `%d{client_tls_sig_non_pqc_offers}` | Whether the client offered a non-PQC digital signature algorithm | `0 or 1` |
| `%d{client_tls_sig_hybrid_offers}` | Whether the client offered a hybrid digital signature algorithm | `0 or 1` |
| `%d{client_tls_sig_unknown_offers}` | Whether the client offered an unknown digital signature algorithm | `0 or 1` |
| `%s{client_tls_keyex_alg}` | TLS client key exchange algorithm | `X23319LMKEM788` |
| `%s{client_tls_sig_alg}` | TLS client digital signature algorithm | `rsa_pss_rsae_sha256` |

## Server Connection

| Field | Meaning | Example |
|---|---|---|
| `%s{srvsslcipher}` | Negotiated cipher suite, Zscaler<->server | `SSL3_CK_RSA_NULL_SHA` |
| `%s{srvtlsversion}` | TLS version, Public Service Edge<->server | `SSL2, SSL3, TLS1_1, TLS1_2, TLS1_3` |
| `%s{serversslsessreuse}` | Server cipher reuse information | `Unknown, No, Yes` |
| `%s{srvocspresult}` | OCSP result/certificate revocation result | `Good, Revoked, Unknown` |
| `%s{srvcertchainvalpass}` | Validation of the certificate chain | `Unknown, Fail, Pass` |
| `%s{srvwildcardcert}` | Whether the server certificate is a wildcard cert | `Unknown, No, Yes` |
| `%s{srvcertvalidationtype}` | Validation method of the server certificate | `EV, OV, DV` |
| `%s{srvcertvalidityperiod}` | Expiration of the server certificate | `Short (0-3mo), Medium (3-12mo), Long (12mo+)` |
| `%s{is_ssluntrustedca}` | Whether the server cert is signed by a Zscaler-trusted CA | `Fail, Pass, None` |
| `%s{is_sslselfsigned}` | Whether the server-presented cert is self-signed | `No, None, Yes` |
| `%s{is_sslexpiredca}` | Whether the server-presented cert is expired | `No, None, Yes` |
| `%s{server_tls_keyex_alg}` | TLS server key exchange algorithm | `X23319LMKEM788` |
| `%s{server_tls_sig_alg}` | TLS server digital signature algorithm | `rsa_pss_rsae_sha256` |

## Threat Protection

| Field | Meaning | Example |
|---|---|---|
| `%d{riskscore}` | Page Risk Index score of the destination URL, 0-100 | `10` |
| `%s{threatseverity}` | Threat severity, derived from `riskscore`: Critical 90-100, High 75-89, Medium 46-74, Low 1-45, None 0 | `Critical` |
| `%s{threatname}` | Name of the detected threat, if any | `EICAR Test File` |
| `%s{malwarecat}` | Category of malware detected ("Threat Category" in Insights Logs) | `Adware, Benign, Trojan` |
| `%s{malwareclass}` | Class of malware detected ("Threat Super Category" in Insights Logs) | `Sandbox` |
| `%s{ai_ml_detect_src}` | AI/ML detection source for the transaction | `AI/ML - ATP - Phishing` |

## URL Categorization

| Field | Meaning | Example |
|---|---|---|
| `%s{urlclass}` | Class of the destination URL | `Bandwidth Loss, General Surfing, Privacy Risk` |
| `%s{urlsupercat}` | Super category of the destination URL | `Entertainment/Recreation, Travel, Security` |
| `%s{urlcat}` | Category of the destination URL, also carries the Advanced Threat Category | `Entertainment, Adult Themes, Spyware Callback` |
| `%s{urlcatmethod}` | Source of the URL's category | `Database A, Database B, AI/ML-based content categorization, User-Defined, None` |

## Zscaler Client Connector Device Information

**The device/asset section** — everything this task's tag bank draws on.

| Field | Meaning | Example |
|---|---|---|
| `%s{devicehostname}` | Hostname of the device | `THINKPADSMITH` |
| `%s{devicemodel}` | Model of the device | `20L8S7WC08` |
| `%s{devicename}` | Name of the device (opaque, hash-suffixed identifier) | `PC11NLPA:5F08D97BBF43257A8FB4BBF4061A38AE324EF734` |
| `%s{devicetype}` | Type of device | `Zscaler Client Connector` |
| `%s{deviceostype}` | OS type of the device (5-value enum) | `iOS, Android OS, Windows OS, MAC OS, Other OS` |
| `%s{deviceosversion}` | OS version the device uses | `Version 10.14.2 (Build 18C54)` |
| `%s{deviceowner}` | Owner of the device | `jsmith` |
| `%s{deviceappversion}` | Client Connector app version enrolled on the device | `2.0.0.120` |

## Miscellaneous (continued device/tunnel fields)

| Field | Meaning | Example |
|---|---|---|
| `%s{ztunnelversion}` | Z-Tunnel version | `ZTUNNEL_1_0` |
| `%s{external_devid}` | External device ID associating the user's device with an MDM solution | `1234` |
| `%d{bypassed_traffic}` | Whether traffic bypassed the Zscaler Client Connector (1) or not (0) | `1 / 0` |
| `%s{bypassed_etime}` | Date/time the traffic bypassed the Client Connector | `Mon Oct 16 22:55:48 2023` |
| `%s{flow_type}` | Flow type of the transaction | `Direct, Loopback, VPN, VPN Tunnel, ZIA, ZPA` |
| `%d{recordid}` | Unique record identifier for each log (NSS-specific) | — |
| `%s{pcapid}` | Path of the PCAP file that captured the transaction | `43139974/web/663ba8fd30b50001.pcap` |
| `%s{productversion}` | Current product version (NSS-specific) | `5.0.902.95524_04` |
| `%s{nsssvcip}` | Service IP address of the NSS (NSS-specific) | `10.10.102.300` |
| `%s{eedone}` | Whether Feed Escape Character fields were hex-encoded (NSS-specific) | `Yes` |

## Obfuscated Fields

Select fields support an obfuscation prefix `o` — e.g. `%d{ocip}` is the obfuscated version of
`%s{cip}`; instead of the real value, NSS emits a random string:

`%s{olog in}`, `%s{obwclassname}`, `%s{odlpdict}`, `%s{odlpeng}`, `%s{odlprulename}`,
`%s{ordr_rulename}`, `%s{ofwd_gw_name}`, `%s{ozpa_app_seg_name}`, `%d{ocip}`, `%d{ocpubip}`,
`%s{ourlfilterrulelabel}`, `%s{oapprulelabel}`, `%s{ourlcat}`, `%s{odevicehostname}`,
`%s{odevicename}`, `%s{odeviceowner}`

## Base64 Fields

For fields where URL encoding isn't suitable, NSS can Base64-encode the value (config note:
turning this on for every supported field costs ~20% throughput):

`%s{b64ua}`, `%s{b64filename}`, `%s{b64upload_filename}`, `%s{b64threatname}`,
`%s{b64mobappname}`, `%s{b64host}`, `%s{b64url}`, `%s{b64referer}`, `%s{b64login}`,
`%s{b64location}`, `%s{b64dept}`, `%s{b64urlcat}`, `%s{b64rulelabel}`,
`%s{b64urlfilterrulelabel}`, `%s{b64apprulelabel}`, `%s{b64dlprulename}`, `%s{b64rdr_rulename}`,
`%s{b64fwd_gw_name}`, `%s{b64zpa_app_seg_name}`, `%s{b64userlocationname}`

## Hex-Encoded Fields

Zscaler hex-encodes every non-printable ASCII character (<= `0x20` or >= `0x7F`) in a URL as
`%HH` (a `\n` becomes `%0A`, a space becomes `%20`). The following fields carry hex-encoded URLs:

`%s{eua}`, `%s{efilename}`, `%s{eupload_filename}`, `%s{emobappname}`, `%s{ehost}`, `%s{eurl}`,
`%s{ereferer}`, `%s{erefererpath}`, `%s{eurlpath}`, `%s{erefererhost}`, `%s{elogin}`,
`%s{elocation}`, `%s{edepartment}`, `%s{erulelabel}`, `%s{eurlfilterrulelabel}`,
`%s{eapprulelabel}`, `%s{euserlocationname}`, `%s{edevicename}`, `%s{edevicehostname}`,
`%s{eprompt_req}`

---

## Task 2 — reconciliation against what we actually parse

**Question**: our parser (`app/parsers/zscaler.py`) and generator (`backend/datagen/emitters/
zscaler.py`) use field names like `user`, `department`, `host`, `clientip`, `serverip` — this doc
says `login`, `dept`. Is that (a) genuine drift in this project, or (b) a real, documented NSS
output variant?

**Verdict: (b), and it is not our own drift.** Of the parser's original 25 canonical fields, 10
are *literal* tokens from this PDF (`host`, `url`, `action`, `appname`, `appclass`, `threatname`,
`riskscore`, `reason`, `referer`, `location`). The other 15 (`user`, `clientip`, `serverip`,
`requestmethod`, `status`, `requestsize`, `responsesize`, `useragent`, `urlcategory`,
`urlsupercategory`, `threatcategory`, `dlpengine`, `dlpdictionaries`, `department`) are **not**
literal tokens in this PDF — the PDF's own names for the same concepts are `login`, `cip`, `sip`,
`reqmethod`, `respcode` *(no field literally named `status`)*, `reqsize`, `respsize`, `ua`,
`urlcat`, `urlsupercat`, `malwarecat` *(no field literally named `threatcategory`)*, `dlpeng`,
`dlpdict`, `dept`.

Evidence this is a real, independently-attested SIEM-side naming convention rather than an
invented one: a live, published parser knowledge base for a Zscaler WebProxy log source
(Cyderes, an MDR vendor's own parser documentation, fetched directly) lists its raw/source field
names as including — verbatim — `clientip`, `serverip`, `requestmethod`, `requestsize`,
`responsesize`, `useragent`, `department`, `dlpdictionaries`, `threatcategory`, `user`,
`urlcategory`, `urlsupercategory`, `appname`, `appclass`, `dlpengine`, `location`, `action`,
`hostname`, `host`(name), `reason` — the same renaming pattern end to end (`login`→`user`,
`dept`→`department`, `cip`→`clientip`, `sip`→`serverip`, `reqmethod`→`requestmethod`,
`reqsize`→`requestsize`, `respsize`→`responsesize`, `ua`→`useragent`, (no literal `status`
token)→`status`, `urlcat`→`urlcategory`, `urlsupercat`→`urlsupercategory`,
`malwarecat`→`threatcategory`, `dlpdict`→`dlpdictionaries`, `dlpeng`→`dlpengine`). This is too
specific and too consistent to be coincidence: it is the common "friendlier normalized field
name" convention third-party SIEM/MDR parsers apply on top of Zscaler's own terse NSS tokens when
building their own Common-Information-Model-style schema for the **key=value-formatted** NSS feed
— a genuinely different (and, per the project's own earlier investigation, Exabeam-documented)
output convention from the raw CSV token names this PDF's own tables enumerate, not this
project's invention.

One honest caveat: attempts to independently re-verify the specific *Exabeam* attribution by
fetching Zscaler's own "Zscaler and Exabeam Deployment Guide" PDF returned only marketing/design
assets (cover art, color swatches), not a field-mapping table — that document did not corroborate
or refute the claim either way. The Cyderes evidence above is a different, independently-found
primary source that shows the exact same convention live in production, which is what this
verdict rests on.

**Conclusion for this task**: no rename. The original 25 fields keep their existing (SIEM-
normalized) names — a rename now would break every parser fixture and the round-trip test for a
"fix" that would actually be reverting a legitimate variant back to a less-legible one. The seven
new device/asset fields this task adds use the PDF's own literal tokens instead
(`devicehostname`, `devicename`, `deviceostype`, `deviceosversion`, `deviceowner`,
`bypassed_traffic`, `flow_type`) — there is no prior "friendly" convention to preserve continuity
with for a field this parser never emitted before, so the literal NSS token is the more honest,
lower-risk choice.

## What this task wired in vs. catalogued only

Of everything above, the device/asset hot-column + tag-bank change wires in exactly seven new
fields: `devicehostname`, `devicename`, `deviceostype`, `deviceosversion`, `deviceowner`,
`bypassed_traffic`, `flow_type`. Everything else in this document — DLP, sandbox, TLS/cipher
detail, mobile application — is catalogued for completeness (this doc's whole purpose) but not
parsed: CLAUDE.md's "do not add a tag just because a field exists" applies equally to *fields*,
and none of the un-wired ones back a tag, a detector, or an evidence citation this pipeline needs
today. `devicemodel`, `devicetype`, `deviceappversion`, `ztunnelversion`, `external_devid`,
`bypassed_etime` are the same story within the device section specifically — catalogued above,
not wired.

---

## Encoding variants — parsed by a concurrent change

A second, independent change (landed in this same file/parser alongside the device-field work
above) wires the Obfuscated/Base64/Hex-Encoded Field variants into `app/parsers/zscaler.py` for
the fields this parser already maps. Recorded here rather than in a second doc, since it is the
same source PDF's appendices (pp. 37-39) this file already transcribes above.

**Why it matters**: a real NSS export is configured per field — an administrator can turn on
Base64 or Hex encoding for any one mapped column independently (e.g. request `b64host` instead of
`host`). Before this change, that value would have been ingested as a literal, undecoded string —
a real correctness bug that silently corrupts every domain-keyed detector (beaconing, DGA,
rarity, the entity graph) the moment a customer turns on Base64/Hex encoding for anything.
`app.parsers.zscaler.bind_header` is header-driven (rebuilds the field->index map from the
literal header row it's given), so `b64host`/`ehost`/`host` are three different keys of the same
parsed dict — `_resolve_encoded` looks for the plain key first, then scans an alias table for
whichever encoded variant is present, and decodes it into the same canonical field the plain
value would have landed in.

**Coverage**: of the fields this parser already maps, 8 have a documented Base64 variant (`ua`,
`host`, `url`, `referer`, `login`, `location`, `dept`, `urlcat`), 7 have a documented Hex variant
(the same list minus `urlcat`, plus `department`'s own `edepartment`), and 5 have a documented
Obfuscated variant (`login`, `cip`, `urlcat`, `dlpeng`, `dlpdict`). Device/asset-field encoded
variants (`odevicehostname`, `edevicehostname`, `odevicename`, `edevicename`, `odeviceowner`) are
deliberately **excluded** from this change's alias table — that field family belongs to the
device-field change above, by agreement between the two.

**Decoding**:
- **Base64** (`base64.b64decode(..., validate=True)`, rejecting non-alphabet characters rather
  than silently discarding them) then UTF-8-decoded.
- **Hex** — walks the string, validates every `%` escape is followed by exactly two hex digits,
  accumulates raw bytes (so a multi-byte UTF-8 character with every byte individually escaped
  still reassembles), then UTF-8-decodes once.
- Either failure mode (malformed base64/hex, or bytes that don't form valid UTF-8) is a recorded
  `ParseFailure`, never a silent pass-through of the encoded literal or garbage bytes as if they
  were the real field.

**Obfuscated fields are nulled, not decoded — because they can't be.** Per the spec's own words,
an obfuscated value is "a random string" standing in for the real one, not a reversible encoding.
The canonical field is set to `None` (never fed to a hot column, an entity, or a detector join
key — joining on a random per-line token either fabricates false-distinct identities or, if a
token happens to repeat, a false join between unrelated events), and the fact that the field
arrived obfuscated is recorded in `unmapped.obfuscated_fields` (a sorted list of canonical field
names) rather than silently dropped — a customer running with `ologin` turned on loses all
user-level detection, and that should be visible somewhere, not just inferred from the absence of
signals.

**Contradictions found while wiring this up**, recorded rather than silently worked around:

1. **`malwarecat` is not `threatcategory`.** This doc's own Threat Protection section (and
   Task 2's reconciliation above) already notes the PDF has no field literally named
   `threatcategory` — it has `malwarecat` ("The category of malware... e.g. Adware, Benign,
   Trojan") and a separate `malwareclass` ("Threat Super Category"). Our OCSF mapping's
   `threatcategory` is this parser's own best-effort name for `malwarecat`'s concept, not a
   literal match — worth a dedicated look before anything wires up `malwareclass` too, so the two
   don't end up describing the same slot two different ways.
2. **`refererhost` exists as its own field** (PDF p.16, "The hostname of the referrer URL"),
   distinct from `referer` (the full URL). Our OCSF mapping only carries the whole `referer`
   string into `http_request.referrer` — `refererhost` is not separately parsed.
3. **`eurlpath`/`erefererpath`/`erefererhost` have no plain-field counterparts.** The
   Hex-Encoded Fields section documents these three, but the HTTP Transaction section's
   plain-field table has no `urlpath`, `refererpath`, or second `refererhost` token to pair them
   with. Read as Zscaler's own internal derived sub-fields that only exist in hex-encoded form in
   this feed — not wired into this parser.
4. **`cpubip` ("client public IP")** has a documented obfuscated variant (`ocpubip`) but no plain
   mapping in our parser at all — only `cip` is read. A customer obfuscating `cpubip` would
   currently produce nothing observable either way; not fixed here (new field coverage, not an
   encoding-correctness fix for a field already mapped).

---

## Phase 2 — the twenty detection fields, landed (encoding-variant task, this same change)

The section-by-section inventory above marks several fields "Phase 2 candidate" — as of this
change those candidates are wired end to end (parse → OCSF → `events` → generator → corpus), per
the encoding-variant task's second half. No detector reads any of them yet (CLAUDE.md: land the
data, don't ship a detector in the same change) — see that task's own report for the per-field
detector-design note. Landed:

| Field(s) | OCSF path | Notes |
|---|---|---|
| `ja4_str` | `tls.ja4_hash`, hot column `events.ja4_hash` | The only Phase 2 field promoted to an indexed hot column — "a better cross-tenant Tier 2 indicator than a domain" per this task's own brief |
| `df_hostname` / `df_hosthead` | top-level `df_hostname` / `df_hosthead` (no OCSF-taxonomy home, same treatment `flow_type` got) | Generator never populates these on benign traffic — presence alone is the signal |
| `ssldecrypted`, `is_sslselfsigned`, `is_sslexpiredca`, `is_ssluntrustedca`, `srvcertvalidityperiod`, `srvocspresult` | `tls.decrypted`, `tls.certificate.*` | `is_ssluntrustedca`'s wire values are `Fail`/`Pass`, not `Yes`/`No` — `Fail → True` ("is untrusted"); see `app.ocsf.common.Certificate`'s docstring |
| `sha256`, `bamd5` | `file.hash_sha256`, `file.hash_md5` | Route through `pseudonymize.indicator_hash`'s shared salt at the LLM/Tier 2 boundary, not the per-tenant one (docs/06) |
| `srcip_country`, `dstip_country`, `is_src_cntry_risky`, `is_dst_cntry_risky` | `src_endpoint.location.{country,is_risky}`, `dst_endpoint.location.{country,is_risky}` | Vendor-reported, independent of the offline MaxMind enrichment pass on `src_ip`/`dst_ip` — can legitimately disagree with it |
| `upload_filename`, `upload_filetype`, `filetype`, `unscannabletype` | `file.name`, `file.upload_type`, `file.download_type`, `file.unscannable_type` | `upload_filename` is the one Phase 2 field with a documented encoded variant (`b64upload_filename`/`eupload_filename`) — wired into the same alias table the twelve original-25 fields use |
| `threatseverity` | top-level `threat_severity` | Parsed as sent, not recomputed from `riskscore` — the feed's own bucketing (Critical/High/Medium/Low/None) is trusted as reported |

**`malwarecat` deliberately not added.** "Task 2 — reconciliation" above already found that this
parser's existing `threatcategory` (mapped since before this task, `malware[].classification_ids`)
is this codebase's own name for the PDF's `malwarecat` concept — adding a second `malwarecat`
field would describe the same slot twice. `malwareclass` ("Threat Super Category") is a genuinely
distinct field but was not in the encoding-variant task's requested Phase 2 list and was not
added, to avoid scope creep beyond what was asked.

**Generator realism, briefly** (`datagen/emitters/zscaler.py`): JA4 is derived deterministically
per browser/OS cohort (`_ja4_fingerprint`) so many benign users on the same browser+OS share one
fingerprint — realistic clustering, and what makes a *rare* JA4 recurring across otherwise-
unrelated domains a real anomaly rather than a generator artifact. Certificate posture, geo, and
threat severity are populated on (almost) every benign event with realistic values (trusted/
non-expired/non-self-signed certs, non-risky countries); file hashes and upload metadata are
sparse, gated on download/upload-shaped requests, matching real-world rarity. The malicious
profile — one implant JA4 held constant across `s09_multi_domain_c2_failover`'s rotating sibling
domains, paired with a self-signed/untrusted/short-validity certificate, plus a reused EICAR-hash
file indicator in `s01_c2_beaconing`'s upload check-ins — is injected by those two scenario
modules via `build_event`'s `extra=` escape hatch, not by any change to the benign path.
