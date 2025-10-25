# Nmap 7.98 scan initiated Wed Oct 22 20:48:58 2025 as: nmap -n -Pn -sT -sV --script vuln --reason -oA metspl-ubu 192.168.56.3
Nmap scan report for 192.168.56.3
Host is up, received user-set (0.00048s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT     STATE  SERVICE     REASON       VERSION
21/tcp   open   ftp         syn-ack      ProFTPD 1.3.5
| vulners: 
|   cpe:/a:proftpd:proftpd:1.3.5: 
|     	SAINT:FD1752E124A72FD3A26EEB9B315E8382	10.0	https://vulners.com/saint/SAINT:FD1752E124A72FD3A26EEB9B315E8382	*EXPLOIT*
|     	SAINT:950EB68D408A40399926A4CCAD3CC62E	10.0	https://vulners.com/saint/SAINT:950EB68D408A40399926A4CCAD3CC62E	*EXPLOIT*
|     	SAINT:63FB77B9136D48259E4F0D4CDA35E957	10.0	https://vulners.com/saint/SAINT:63FB77B9136D48259E4F0D4CDA35E957	*EXPLOIT*
|     	SAINT:1B08F4664C428B180EEC9617B41D9A2C	10.0	https://vulners.com/saint/SAINT:1B08F4664C428B180EEC9617B41D9A2C	*EXPLOIT*
|     	PROFTPD_MOD_COPY	10.0	https://vulners.com/canvas/PROFTPD_MOD_COPY	*EXPLOIT*
|     	PACKETSTORM:162777	10.0	https://vulners.com/packetstorm/PACKETSTORM:162777	*EXPLOIT*
|     	PACKETSTORM:132218	10.0	https://vulners.com/packetstorm/PACKETSTORM:132218	*EXPLOIT*
|     	PACKETSTORM:131567	10.0	https://vulners.com/packetstorm/PACKETSTORM:131567	*EXPLOIT*
|     	PACKETSTORM:131555	10.0	https://vulners.com/packetstorm/PACKETSTORM:131555	*EXPLOIT*
|     	PACKETSTORM:131505	10.0	https://vulners.com/packetstorm/PACKETSTORM:131505	*EXPLOIT*
|     	MSF:EXPLOIT-UNIX-FTP-PROFTPD_MODCOPY_EXEC-	10.0	https://vulners.com/metasploit/MSF:EXPLOIT-UNIX-FTP-PROFTPD_MODCOPY_EXEC-	*EXPLOIT*
|     	EDB-ID:49908	10.0	https://vulners.com/exploitdb/EDB-ID:49908	*EXPLOIT*
|     	EDB-ID:37262	10.0	https://vulners.com/exploitdb/EDB-ID:37262	*EXPLOIT*
|     	CVE-2015-3306	10.0	https://vulners.com/cve/CVE-2015-3306
|     	BC7F9971-F233-5C1A-AA5E-DAA7587C7DED	10.0	https://vulners.com/githubexploit/BC7F9971-F233-5C1A-AA5E-DAA7587C7DED	*EXPLOIT*
|     	1337DAY-ID-36298	10.0	https://vulners.com/zdt/1337DAY-ID-36298	*EXPLOIT*
|     	1337DAY-ID-23720	10.0	https://vulners.com/zdt/1337DAY-ID-23720	*EXPLOIT*
|     	1337DAY-ID-23544	10.0	https://vulners.com/zdt/1337DAY-ID-23544	*EXPLOIT*
|     	CVE-2024-48651	7.5	https://vulners.com/cve/CVE-2024-48651
|     	CVE-2023-51713	7.5	https://vulners.com/cve/CVE-2023-51713
|     	CVE-2021-46854	7.5	https://vulners.com/cve/CVE-2021-46854
|     	CVE-2020-9272	7.5	https://vulners.com/cve/CVE-2020-9272
|     	CVE-2019-19272	7.5	https://vulners.com/cve/CVE-2019-19272
|     	CVE-2019-19271	7.5	https://vulners.com/cve/CVE-2019-19271
|     	CVE-2019-19270	7.5	https://vulners.com/cve/CVE-2019-19270
|     	CVE-2019-18217	7.5	https://vulners.com/cve/CVE-2019-18217
|     	CVE-2016-3125	7.5	https://vulners.com/cve/CVE-2016-3125
|     	CNVD-2020-14677	7.5	https://vulners.com/cnvd/CNVD-2020-14677
|     	CNVD-2019-44557	7.5	https://vulners.com/cnvd/CNVD-2019-44557
|     	CVE-2023-48795	5.9	https://vulners.com/cve/CVE-2023-48795
|     	CVE-2017-7418	5.5	https://vulners.com/cve/CVE-2017-7418
|     	SSV:61050	5.0	https://vulners.com/seebug/SSV:61050	*EXPLOIT*
|_    	CVE-2013-4359	5.0	https://vulners.com/cve/CVE-2013-4359
22/tcp   open   ssh         syn-ack      OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:6.6.1p1: 
|     	DF059135-2CF5-5441-8F22-E6EF1DEE5F6E	10.0	https://vulners.com/gitee/DF059135-2CF5-5441-8F22-E6EF1DEE5F6E	*EXPLOIT*
|     	PACKETSTORM:173661	9.8	https://vulners.com/packetstorm/PACKETSTORM:173661	*EXPLOIT*
|     	F0979183-AE88-53B4-86CF-3AF0523F3807	9.8	https://vulners.com/githubexploit/F0979183-AE88-53B4-86CF-3AF0523F3807	*EXPLOIT*
|     	CVE-2023-38408	9.8	https://vulners.com/cve/CVE-2023-38408
|     	CVE-2016-1908	9.8	https://vulners.com/cve/CVE-2016-1908
|     	B8190CDB-3EB9-5631-9828-8064A1575B23	9.8	https://vulners.com/githubexploit/B8190CDB-3EB9-5631-9828-8064A1575B23	*EXPLOIT*
|     	8FC9C5AB-3968-5F3C-825E-E8DB5379A623	9.8	https://vulners.com/githubexploit/8FC9C5AB-3968-5F3C-825E-E8DB5379A623	*EXPLOIT*
|     	8AD01159-548E-546E-AA87-2DE89F3927EC	9.8	https://vulners.com/githubexploit/8AD01159-548E-546E-AA87-2DE89F3927EC	*EXPLOIT*
|     	2227729D-6700-5C8F-8930-1EEAFD4B9FF0	9.8	https://vulners.com/githubexploit/2227729D-6700-5C8F-8930-1EEAFD4B9FF0	*EXPLOIT*
|     	0221525F-07F5-5790-912D-F4B9E2D1B587	9.8	https://vulners.com/githubexploit/0221525F-07F5-5790-912D-F4B9E2D1B587	*EXPLOIT*
|     	CVE-2015-5600	8.5	https://vulners.com/cve/CVE-2015-5600
|     	BA3887BD-F579-53B1-A4A4-FF49E953E1C0	8.1	https://vulners.com/githubexploit/BA3887BD-F579-53B1-A4A4-FF49E953E1C0	*EXPLOIT*
|     	4FB01B00-F993-5CAF-BD57-D7E290D10C1F	8.1	https://vulners.com/githubexploit/4FB01B00-F993-5CAF-BD57-D7E290D10C1F	*EXPLOIT*
|     	PACKETSTORM:140070	7.8	https://vulners.com/packetstorm/PACKETSTORM:140070	*EXPLOIT*
|     	EXPLOITPACK:5BCA798C6BA71FAE29334297EC0B6A09	7.8	https://vulners.com/exploitpack/EXPLOITPACK:5BCA798C6BA71FAE29334297EC0B6A09	*EXPLOIT*
|     	EDB-ID:40888	7.8	https://vulners.com/exploitdb/EDB-ID:40888	*EXPLOIT*
|     	CVE-2020-15778	7.8	https://vulners.com/cve/CVE-2020-15778
|     	CVE-2016-6515	7.8	https://vulners.com/cve/CVE-2016-6515
|     	CVE-2016-10012	7.8	https://vulners.com/cve/CVE-2016-10012
|     	CVE-2015-8325	7.8	https://vulners.com/cve/CVE-2015-8325
|     	C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3	7.8	https://vulners.com/githubexploit/C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3	*EXPLOIT*
|     	312165E3-7FD9-5769-BDA3-4129BE9114D6	7.8	https://vulners.com/githubexploit/312165E3-7FD9-5769-BDA3-4129BE9114D6	*EXPLOIT*
|     	2E719186-2FED-58A8-A150-762EFBAAA523	7.8	https://vulners.com/gitee/2E719186-2FED-58A8-A150-762EFBAAA523	*EXPLOIT*
|     	23CC97BE-7C95-513B-9E73-298C48D74432	7.8	https://vulners.com/githubexploit/23CC97BE-7C95-513B-9E73-298C48D74432	*EXPLOIT*
|     	1337DAY-ID-26494	7.8	https://vulners.com/zdt/1337DAY-ID-26494	*EXPLOIT*
|     	10213DBE-F683-58BB-B6D3-353173626207	7.8	https://vulners.com/githubexploit/10213DBE-F683-58BB-B6D3-353173626207	*EXPLOIT*
|     	SSV:92579	7.5	https://vulners.com/seebug/SSV:92579	*EXPLOIT*
|     	CVE-2016-10708	7.5	https://vulners.com/cve/CVE-2016-10708
|     	CVE-2016-10009	7.5	https://vulners.com/cve/CVE-2016-10009
|     	CF52FA19-B5DB-5D14-B50F-2411851976E2	7.5	https://vulners.com/githubexploit/CF52FA19-B5DB-5D14-B50F-2411851976E2	*EXPLOIT*
|     	1337DAY-ID-26576	7.5	https://vulners.com/zdt/1337DAY-ID-26576	*EXPLOIT*
|     	SSV:92582	7.2	https://vulners.com/seebug/SSV:92582	*EXPLOIT*
|     	CVE-2021-41617	7.0	https://vulners.com/cve/CVE-2021-41617
|     	CVE-2016-10010	7.0	https://vulners.com/cve/CVE-2016-10010
|     	284B94FC-FD5D-5C47-90EA-47900DAD1D1E	7.0	https://vulners.com/githubexploit/284B94FC-FD5D-5C47-90EA-47900DAD1D1E	*EXPLOIT*
|     	SSV:92580	6.9	https://vulners.com/seebug/SSV:92580	*EXPLOIT*
|     	CVE-2015-6564	6.9	https://vulners.com/cve/CVE-2015-6564
|     	1337DAY-ID-26577	6.9	https://vulners.com/zdt/1337DAY-ID-26577	*EXPLOIT*
|     	EDB-ID:46516	6.8	https://vulners.com/exploitdb/EDB-ID:46516	*EXPLOIT*
|     	EDB-ID:46193	6.8	https://vulners.com/exploitdb/EDB-ID:46193	*EXPLOIT*
|     	CVE-2019-6110	6.8	https://vulners.com/cve/CVE-2019-6110
|     	CVE-2019-6109	6.8	https://vulners.com/cve/CVE-2019-6109
|     	1337DAY-ID-32328	6.8	https://vulners.com/zdt/1337DAY-ID-32328	*EXPLOIT*
|     	1337DAY-ID-32009	6.8	https://vulners.com/zdt/1337DAY-ID-32009	*EXPLOIT*
|     	D104D2BF-ED22-588B-A9B2-3CCC562FE8C0	6.5	https://vulners.com/githubexploit/D104D2BF-ED22-588B-A9B2-3CCC562FE8C0	*EXPLOIT*
|     	CVE-2023-51385	6.5	https://vulners.com/cve/CVE-2023-51385
|     	C07ADB46-24B8-57B7-B375-9C761F4750A2	6.5	https://vulners.com/githubexploit/C07ADB46-24B8-57B7-B375-9C761F4750A2	*EXPLOIT*
|     	A88CDD3E-67CC-51CC-97FB-AB0CACB6B08C	6.5	https://vulners.com/githubexploit/A88CDD3E-67CC-51CC-97FB-AB0CACB6B08C	*EXPLOIT*
|     	65B15AA1-2A8D-53C1-9499-69EBA3619F1C	6.5	https://vulners.com/githubexploit/65B15AA1-2A8D-53C1-9499-69EBA3619F1C	*EXPLOIT*
|     	5325A9D6-132B-590C-BDEF-0CB105252732	6.5	https://vulners.com/gitee/5325A9D6-132B-590C-BDEF-0CB105252732	*EXPLOIT*
|     	530326CF-6AB3-5643-AA16-73DC8CB44742	6.5	https://vulners.com/githubexploit/530326CF-6AB3-5643-AA16-73DC8CB44742	*EXPLOIT*
|     	EDB-ID:40858	6.4	https://vulners.com/exploitdb/EDB-ID:40858	*EXPLOIT*
|     	EDB-ID:40119	6.4	https://vulners.com/exploitdb/EDB-ID:40119	*EXPLOIT*
|     	EDB-ID:39569	6.4	https://vulners.com/exploitdb/EDB-ID:39569	*EXPLOIT*
|     	CVE-2016-3115	6.4	https://vulners.com/cve/CVE-2016-3115
|     	PACKETSTORM:181223	5.9	https://vulners.com/packetstorm/PACKETSTORM:181223	*EXPLOIT*
|     	MSF:AUXILIARY-SCANNER-SSH-SSH_ENUMUSERS-	5.9	https://vulners.com/metasploit/MSF:AUXILIARY-SCANNER-SSH-SSH_ENUMUSERS-	*EXPLOIT*
|     	EDB-ID:40136	5.9	https://vulners.com/exploitdb/EDB-ID:40136	*EXPLOIT*
|     	EDB-ID:40113	5.9	https://vulners.com/exploitdb/EDB-ID:40113	*EXPLOIT*
|     	CVE-2023-48795	5.9	https://vulners.com/cve/CVE-2023-48795
|     	CVE-2020-14145	5.9	https://vulners.com/cve/CVE-2020-14145
|     	CVE-2019-6111	5.9	https://vulners.com/cve/CVE-2019-6111
|     	CVE-2016-6210	5.9	https://vulners.com/cve/CVE-2016-6210
|     	CNVD-2021-25272	5.9	https://vulners.com/cnvd/CNVD-2021-25272
|     	A02ABE85-E4E3-5852-A59D-DF288CB8160A	5.9	https://vulners.com/githubexploit/A02ABE85-E4E3-5852-A59D-DF288CB8160A	*EXPLOIT*
|     	6D74A425-60A7-557A-B469-1DD96A2D8FF8	5.9	https://vulners.com/githubexploit/6D74A425-60A7-557A-B469-1DD96A2D8FF8	*EXPLOIT*
|     	EXPLOITPACK:98FE96309F9524B8C84C508837551A19	5.8	https://vulners.com/exploitpack/EXPLOITPACK:98FE96309F9524B8C84C508837551A19	*EXPLOIT*
|     	EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97	5.8	https://vulners.com/exploitpack/EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97	*EXPLOIT*
|     	SSV:91041	5.5	https://vulners.com/seebug/SSV:91041	*EXPLOIT*
|     	PACKETSTORM:140019	5.5	https://vulners.com/packetstorm/PACKETSTORM:140019	*EXPLOIT*
|     	PACKETSTORM:136251	5.5	https://vulners.com/packetstorm/PACKETSTORM:136251	*EXPLOIT*
|     	PACKETSTORM:136234	5.5	https://vulners.com/packetstorm/PACKETSTORM:136234	*EXPLOIT*
|     	EXPLOITPACK:F92411A645D85F05BDBD274FD222226F	5.5	https://vulners.com/exploitpack/EXPLOITPACK:F92411A645D85F05BDBD274FD222226F	*EXPLOIT*
|     	EXPLOITPACK:9F2E746846C3C623A27A441281EAD138	5.5	https://vulners.com/exploitpack/EXPLOITPACK:9F2E746846C3C623A27A441281EAD138	*EXPLOIT*
|     	EXPLOITPACK:1902C998CBF9154396911926B4C3B330	5.5	https://vulners.com/exploitpack/EXPLOITPACK:1902C998CBF9154396911926B4C3B330	*EXPLOIT*
|     	CVE-2016-10011	5.5	https://vulners.com/cve/CVE-2016-10011
|     	1337DAY-ID-25388	5.5	https://vulners.com/zdt/1337DAY-ID-25388	*EXPLOIT*
|     	FD18B68B-C0A6-562E-A8C8-781B225F15B0	5.3	https://vulners.com/githubexploit/FD18B68B-C0A6-562E-A8C8-781B225F15B0	*EXPLOIT*
|     	EDB-ID:45939	5.3	https://vulners.com/exploitdb/EDB-ID:45939	*EXPLOIT*
|     	EDB-ID:45233	5.3	https://vulners.com/exploitdb/EDB-ID:45233	*EXPLOIT*
|     	E9EC0911-E2E1-52A7-B2F4-D0065C6A3057	5.3	https://vulners.com/githubexploit/E9EC0911-E2E1-52A7-B2F4-D0065C6A3057	*EXPLOIT*
|     	CVE-2018-20685	5.3	https://vulners.com/cve/CVE-2018-20685
|     	CVE-2018-15919	5.3	https://vulners.com/cve/CVE-2018-15919
|     	CVE-2018-15473	5.3	https://vulners.com/cve/CVE-2018-15473
|     	CVE-2017-15906	5.3	https://vulners.com/cve/CVE-2017-15906
|     	CVE-2016-20012	5.3	https://vulners.com/cve/CVE-2016-20012
|     	CNVD-2018-20962	5.3	https://vulners.com/cnvd/CNVD-2018-20962
|     	CNVD-2018-20960	5.3	https://vulners.com/cnvd/CNVD-2018-20960
|     	A9E6F50E-E7FC-51D0-9C93-A43461469FA2	5.3	https://vulners.com/githubexploit/A9E6F50E-E7FC-51D0-9C93-A43461469FA2	*EXPLOIT*
|     	A801235B-9835-5BA8-B8FE-23B7FFCABD66	5.3	https://vulners.com/githubexploit/A801235B-9835-5BA8-B8FE-23B7FFCABD66	*EXPLOIT*
|     	8DD1D813-FD5A-5B26-867A-CE7CAC9FEEDF	5.3	https://vulners.com/gitee/8DD1D813-FD5A-5B26-867A-CE7CAC9FEEDF	*EXPLOIT*
|     	486BB6BC-9C26-597F-B865-D0E904FDA984	5.3	https://vulners.com/githubexploit/486BB6BC-9C26-597F-B865-D0E904FDA984	*EXPLOIT*
|     	2385176A-820F-5469-AB09-C340264F2B2F	5.3	https://vulners.com/gitee/2385176A-820F-5469-AB09-C340264F2B2F	*EXPLOIT*
|     	1337DAY-ID-31730	5.3	https://vulners.com/zdt/1337DAY-ID-31730	*EXPLOIT*
|     	SSH_ENUM	5.0	https://vulners.com/canvas/SSH_ENUM	*EXPLOIT*
|     	PACKETSTORM:150621	5.0	https://vulners.com/packetstorm/PACKETSTORM:150621	*EXPLOIT*
|     	EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0	5.0	https://vulners.com/exploitpack/EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0	*EXPLOIT*
|     	EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283	5.0	https://vulners.com/exploitpack/EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283	*EXPLOIT*
|     	EXPLOITPACK:802AF3229492E147A5F09C7F2B27C6DF	4.3	https://vulners.com/exploitpack/EXPLOITPACK:802AF3229492E147A5F09C7F2B27C6DF	*EXPLOIT*
|     	EXPLOITPACK:5652DDAA7FE452E19AC0DC1CD97BA3EF	4.3	https://vulners.com/exploitpack/EXPLOITPACK:5652DDAA7FE452E19AC0DC1CD97BA3EF	*EXPLOIT*
|     	CVE-2015-5352	4.3	https://vulners.com/cve/CVE-2015-5352
|     	1337DAY-ID-25440	4.3	https://vulners.com/zdt/1337DAY-ID-25440	*EXPLOIT*
|     	1337DAY-ID-25438	4.3	https://vulners.com/zdt/1337DAY-ID-25438	*EXPLOIT*
|     	CVE-2021-36368	3.7	https://vulners.com/cve/CVE-2021-36368
|     	CVE-2025-61985	3.6	https://vulners.com/cve/CVE-2025-61985
|     	CVE-2025-61984	3.6	https://vulners.com/cve/CVE-2025-61984
|     	B7EACB4F-A5CF-5C5A-809F-E03CCE2AB150	3.6	https://vulners.com/githubexploit/B7EACB4F-A5CF-5C5A-809F-E03CCE2AB150	*EXPLOIT*
|     	4C6E2182-0E99-5626-83F6-1646DD648C57	3.6	https://vulners.com/githubexploit/4C6E2182-0E99-5626-83F6-1646DD648C57	*EXPLOIT*
|     	SSV:92581	2.1	https://vulners.com/seebug/SSV:92581	*EXPLOIT*
|     	CVE-2015-6563	1.9	https://vulners.com/cve/CVE-2015-6563
|     	PACKETSTORM:151227	0.0	https://vulners.com/packetstorm/PACKETSTORM:151227	*EXPLOIT*
|     	PACKETSTORM:140261	0.0	https://vulners.com/packetstorm/PACKETSTORM:140261	*EXPLOIT*
|     	PACKETSTORM:138006	0.0	https://vulners.com/packetstorm/PACKETSTORM:138006	*EXPLOIT*
|     	PACKETSTORM:137942	0.0	https://vulners.com/packetstorm/PACKETSTORM:137942	*EXPLOIT*
|     	1337DAY-ID-30937	0.0	https://vulners.com/zdt/1337DAY-ID-30937	*EXPLOIT*
|     	1337DAY-ID-26468	0.0	https://vulners.com/zdt/1337DAY-ID-26468	*EXPLOIT*
|_    	1337DAY-ID-25391	0.0	https://vulners.com/zdt/1337DAY-ID-25391	*EXPLOIT*
53/tcp   closed domain      conn-refused
80/tcp   open   http        syn-ack      Apache httpd 2.4.7
| http-enum: 
|   /: Root directory w/ listing on 'apache/2.4.7 (ubuntu)'
|   /phpmyadmin/: phpMyAdmin
|_  /uploads/: Potentially interesting directory w/ listing on 'apache/2.4.7 (ubuntu)'
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.56.3
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.56.3:80/drupal/
|     Form id: user-login-form
|     Form action: /drupal/?q=node&destination=node
|     
|     Path: http://192.168.56.3:80/payroll_app.php
|     Form id: 
|     Form action: 
|     
|     Path: http://192.168.56.3:80/chat/
|     Form id: name
|_    Form action: index.php
|_http-server-header: Apache/2.4.7 (Ubuntu)
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
| vulners: 
|   cpe:/a:apache:http_server:2.4.7: 
|     	3E6BA608-776F-5B1F-9BA5-589CD2A5A351	10.0	https://vulners.com/gitee/3E6BA608-776F-5B1F-9BA5-589CD2A5A351	*EXPLOIT*
|     	PACKETSTORM:176334	9.8	https://vulners.com/packetstorm/PACKETSTORM:176334	*EXPLOIT*
|     	PACKETSTORM:171631	9.8	https://vulners.com/packetstorm/PACKETSTORM:171631	*EXPLOIT*
|     	HTTPD:E8492EE5729E8FB514D3C0EE370C9BC6	9.8	https://vulners.com/httpd/HTTPD:E8492EE5729E8FB514D3C0EE370C9BC6
|     	HTTPD:C072933AA965A86DA3E2C9172FFC1569	9.8	https://vulners.com/httpd/HTTPD:C072933AA965A86DA3E2C9172FFC1569
|     	HTTPD:A1BBCE110E077FFBF4469D4F06DB9293	9.8	https://vulners.com/httpd/HTTPD:A1BBCE110E077FFBF4469D4F06DB9293
|     	HTTPD:A09F9CEBE0B7C39EDA0480FEAEF4FE9D	9.8	https://vulners.com/httpd/HTTPD:A09F9CEBE0B7C39EDA0480FEAEF4FE9D
|     	HTTPD:9BCBE3C14201AFC4B0F36F15CB40C0F8	9.8	https://vulners.com/httpd/HTTPD:9BCBE3C14201AFC4B0F36F15CB40C0F8
|     	HTTPD:9AD76A782F4E66676719E36B64777A7A	9.8	https://vulners.com/httpd/HTTPD:9AD76A782F4E66676719E36B64777A7A
|     	HTTPD:650C6B8A1FEAD1FBD1AF9746142659F9	9.8	https://vulners.com/httpd/HTTPD:650C6B8A1FEAD1FBD1AF9746142659F9
|     	HTTPD:2BE0032A6ABE7CC52906DBAAFE0E448E	9.8	https://vulners.com/httpd/HTTPD:2BE0032A6ABE7CC52906DBAAFE0E448E
|     	HTTPD:1F84410918227CC81FA7C000C4F999A3	9.8	https://vulners.com/httpd/HTTPD:1F84410918227CC81FA7C000C4F999A3
|     	HTTPD:156974A46CA46AF26CC4140D00F7EB10	9.8	https://vulners.com/httpd/HTTPD:156974A46CA46AF26CC4140D00F7EB10
|     	EDB-ID:51193	9.8	https://vulners.com/exploitdb/EDB-ID:51193	*EXPLOIT*
|     	D5084D51-C8DF-5CBA-BC26-ACF2E33F8E52	9.8	https://vulners.com/githubexploit/D5084D51-C8DF-5CBA-BC26-ACF2E33F8E52	*EXPLOIT*
|     	CVE-2024-38476	9.8	https://vulners.com/cve/CVE-2024-38476
|     	CVE-2024-38474	9.8	https://vulners.com/cve/CVE-2024-38474
|     	CVE-2023-25690	9.8	https://vulners.com/cve/CVE-2023-25690
|     	CVE-2022-31813	9.8	https://vulners.com/cve/CVE-2022-31813
|     	CVE-2022-23943	9.8	https://vulners.com/cve/CVE-2022-23943
|     	CVE-2022-22720	9.8	https://vulners.com/cve/CVE-2022-22720
|     	CVE-2021-44790	9.8	https://vulners.com/cve/CVE-2021-44790
|     	CVE-2021-39275	9.8	https://vulners.com/cve/CVE-2021-39275
|     	CVE-2021-26691	9.8	https://vulners.com/cve/CVE-2021-26691
|     	CVE-2018-1312	9.8	https://vulners.com/cve/CVE-2018-1312
|     	CVE-2017-7679	9.8	https://vulners.com/cve/CVE-2017-7679
|     	CVE-2017-3169	9.8	https://vulners.com/cve/CVE-2017-3169
|     	CVE-2017-3167	9.8	https://vulners.com/cve/CVE-2017-3167
|     	CNVD-2024-36391	9.8	https://vulners.com/cnvd/CNVD-2024-36391
|     	CNVD-2024-36388	9.8	https://vulners.com/cnvd/CNVD-2024-36388
|     	CNVD-2022-51061	9.8	https://vulners.com/cnvd/CNVD-2022-51061
|     	CNVD-2022-41640	9.8	https://vulners.com/cnvd/CNVD-2022-41640
|     	CNVD-2022-03225	9.8	https://vulners.com/cnvd/CNVD-2022-03225
|     	CNVD-2021-102386	9.8	https://vulners.com/cnvd/CNVD-2021-102386
|     	B6297446-2DDD-52BA-B508-29A748A5D2CC	9.8	https://vulners.com/githubexploit/B6297446-2DDD-52BA-B508-29A748A5D2CC	*EXPLOIT*
|     	64A540A8-D918-5BEA-8F60-987F97B27A0C	9.8	https://vulners.com/githubexploit/64A540A8-D918-5BEA-8F60-987F97B27A0C	*EXPLOIT*
|     	5C1BB960-90C1-5EBF-9BEF-F58BFFDFEED9	9.8	https://vulners.com/githubexploit/5C1BB960-90C1-5EBF-9BEF-F58BFFDFEED9	*EXPLOIT*
|     	3F17CA20-788F-5C45-88B3-E12DB2979B7B	9.8	https://vulners.com/githubexploit/3F17CA20-788F-5C45-88B3-E12DB2979B7B	*EXPLOIT*
|     	1337DAY-ID-39214	9.8	https://vulners.com/zdt/1337DAY-ID-39214	*EXPLOIT*
|     	1337DAY-ID-38427	9.8	https://vulners.com/zdt/1337DAY-ID-38427	*EXPLOIT*
|     	0DB60346-03B6-5FEE-93D7-FF5757D225AA	9.8	https://vulners.com/gitee/0DB60346-03B6-5FEE-93D7-FF5757D225AA	*EXPLOIT*
|     	HTTPD:D868A1E68FB46E2CF5486281DCDB59CF	9.1	https://vulners.com/httpd/HTTPD:D868A1E68FB46E2CF5486281DCDB59CF
|     	HTTPD:509B04B8CC51879DD0A561AC4FDBE0A6	9.1	https://vulners.com/httpd/HTTPD:509B04B8CC51879DD0A561AC4FDBE0A6
|     	HTTPD:2C227652EE0B3B961706AAFCACA3D1E1	9.1	https://vulners.com/httpd/HTTPD:2C227652EE0B3B961706AAFCACA3D1E1
|     	FD2EE3A5-BAEA-5845-BA35-E6889992214F	9.1	https://vulners.com/githubexploit/FD2EE3A5-BAEA-5845-BA35-E6889992214F	*EXPLOIT*
|     	E606D7F4-5FA2-5907-B30E-367D6FFECD89	9.1	https://vulners.com/githubexploit/E606D7F4-5FA2-5907-B30E-367D6FFECD89	*EXPLOIT*
|     	D8A19443-2A37-5592-8955-F614504AAF45	9.1	https://vulners.com/githubexploit/D8A19443-2A37-5592-8955-F614504AAF45	*EXPLOIT*
|     	CVE-2024-40898	9.1	https://vulners.com/cve/CVE-2024-40898
|     	CVE-2024-38475	9.1	https://vulners.com/cve/CVE-2024-38475
|     	CVE-2022-28615	9.1	https://vulners.com/cve/CVE-2022-28615
|     	CVE-2022-22721	9.1	https://vulners.com/cve/CVE-2022-22721
|     	CVE-2017-9788	9.1	https://vulners.com/cve/CVE-2017-9788
|     	CNVD-2024-36387	9.1	https://vulners.com/cnvd/CNVD-2024-36387
|     	CNVD-2024-33814	9.1	https://vulners.com/cnvd/CNVD-2024-33814
|     	CNVD-2022-51060	9.1	https://vulners.com/cnvd/CNVD-2022-51060
|     	CNVD-2022-41638	9.1	https://vulners.com/cnvd/CNVD-2022-41638
|     	B5E74010-A082-5ECE-AB37-623A5B33FE7D	9.1	https://vulners.com/githubexploit/B5E74010-A082-5ECE-AB37-623A5B33FE7D	*EXPLOIT*
|     	5418A85B-F4B7-5BBD-B106-0800AC961C7A	9.1	https://vulners.com/githubexploit/5418A85B-F4B7-5BBD-B106-0800AC961C7A	*EXPLOIT*
|     	HTTPD:1B3D546A8500818AAC5B1359FE11A7E4	9.0	https://vulners.com/httpd/HTTPD:1B3D546A8500818AAC5B1359FE11A7E4
|     	FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8	9.0	https://vulners.com/githubexploit/FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8	*EXPLOIT*
|     	CVE-2022-36760	9.0	https://vulners.com/cve/CVE-2022-36760
|     	CVE-2021-40438	9.0	https://vulners.com/cve/CVE-2021-40438
|     	CNVD-2023-30860	9.0	https://vulners.com/cnvd/CNVD-2023-30860
|     	CNVD-2022-03224	9.0	https://vulners.com/cnvd/CNVD-2022-03224
|     	AE3EF1CC-A0C3-5CB7-A6EF-4DAAAFA59C8C	9.0	https://vulners.com/githubexploit/AE3EF1CC-A0C3-5CB7-A6EF-4DAAAFA59C8C	*EXPLOIT*
|     	8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2	9.0	https://vulners.com/githubexploit/8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2	*EXPLOIT*
|     	7F48C6CF-47B2-5AF9-B6FD-1735FB2A95B2	9.0	https://vulners.com/githubexploit/7F48C6CF-47B2-5AF9-B6FD-1735FB2A95B2	*EXPLOIT*
|     	36618CA8-9316-59CA-B748-82F15F407C4F	9.0	https://vulners.com/githubexploit/36618CA8-9316-59CA-B748-82F15F407C4F	*EXPLOIT*
|     	HTTPD:A7133572D328CD65C350E33F20834FAD	8.2	https://vulners.com/httpd/HTTPD:A7133572D328CD65C350E33F20834FAD
|     	CVE-2021-44224	8.2	https://vulners.com/cve/CVE-2021-44224
|     	CNVD-2021-102387	8.2	https://vulners.com/cnvd/CNVD-2021-102387
|     	B0A9E5E8-7CCC-5984-9922-A89F11D6BF38	8.2	https://vulners.com/githubexploit/B0A9E5E8-7CCC-5984-9922-A89F11D6BF38	*EXPLOIT*
|     	HTTPD:BA2AA2F9CA78BCC3B836D2041D1E15B6	8.1	https://vulners.com/httpd/HTTPD:BA2AA2F9CA78BCC3B836D2041D1E15B6
|     	HTTPD:B63E69E936F944F114293D6F4AB8D4D6	8.1	https://vulners.com/httpd/HTTPD:B63E69E936F944F114293D6F4AB8D4D6
|     	CVE-2024-38473	8.1	https://vulners.com/cve/CVE-2024-38473
|     	CVE-2017-15715	8.1	https://vulners.com/cve/CVE-2017-15715
|     	CVE-2016-5387	8.1	https://vulners.com/cve/CVE-2016-5387
|     	CNVD-2016-04948	8.1	https://vulners.com/cnvd/CNVD-2016-04948
|     	249A954E-0189-5182-AE95-31C866A057E1	8.1	https://vulners.com/githubexploit/249A954E-0189-5182-AE95-31C866A057E1	*EXPLOIT*
|     	23079A70-8B37-56D2-9D37-F638EBF7F8B5	8.1	https://vulners.com/githubexploit/23079A70-8B37-56D2-9D37-F638EBF7F8B5	*EXPLOIT*
|     	PACKETSTORM:181038	7.5	https://vulners.com/packetstorm/PACKETSTORM:181038	*EXPLOIT*
|     	MSF:AUXILIARY-SCANNER-HTTP-APACHE_OPTIONSBLEED-	7.5	https://vulners.com/metasploit/MSF:AUXILIARY-SCANNER-HTTP-APACHE_OPTIONSBLEED-	*EXPLOIT*
|     	HTTPD:F1CFBC9B54DFAD0499179863D36830BB	7.5	https://vulners.com/httpd/HTTPD:F1CFBC9B54DFAD0499179863D36830BB
|     	HTTPD:D5C9AD5E120B9B567832B4A5DBD97F43	7.5	https://vulners.com/httpd/HTTPD:D5C9AD5E120B9B567832B4A5DBD97F43
|     	HTTPD:C317C7138B4A8BBD54A901D6DDDCB837	7.5	https://vulners.com/httpd/HTTPD:C317C7138B4A8BBD54A901D6DDDCB837
|     	HTTPD:C1F57FDC580B58497A5EC5B7D3749F2F	7.5	https://vulners.com/httpd/HTTPD:C1F57FDC580B58497A5EC5B7D3749F2F
|     	HTTPD:B1B0A31C4AD388CC6C575931414173E2	7.5	https://vulners.com/httpd/HTTPD:B1B0A31C4AD388CC6C575931414173E2
|     	HTTPD:975FD708E753E143E7DFFC23510F802E	7.5	https://vulners.com/httpd/HTTPD:975FD708E753E143E7DFFC23510F802E
|     	HTTPD:63F2722DB00DBB3F59C40B40F32363B3	7.5	https://vulners.com/httpd/HTTPD:63F2722DB00DBB3F59C40B40F32363B3
|     	HTTPD:6236A32987BAE49DFBF020477B1278DD	7.5	https://vulners.com/httpd/HTTPD:6236A32987BAE49DFBF020477B1278DD
|     	HTTPD:60420623F2A716909480F87DB74EE9D7	7.5	https://vulners.com/httpd/HTTPD:60420623F2A716909480F87DB74EE9D7
|     	HTTPD:5E6BCDB2F7C53E4EDCE844709D930AF5	7.5	https://vulners.com/httpd/HTTPD:5E6BCDB2F7C53E4EDCE844709D930AF5
|     	HTTPD:34AD734658A873D0B091ED78567E6DF4	7.5	https://vulners.com/httpd/HTTPD:34AD734658A873D0B091ED78567E6DF4
|     	HTTPD:348811594B4FDD8579A34C563A16F7F6	7.5	https://vulners.com/httpd/HTTPD:348811594B4FDD8579A34C563A16F7F6
|     	HTTPD:11D4941ECBB2B14842A64574A692D8D1	7.5	https://vulners.com/httpd/HTTPD:11D4941ECBB2B14842A64574A692D8D1
|     	HTTPD:05E6BF2AD317E3658D2938931207AA66	7.5	https://vulners.com/httpd/HTTPD:05E6BF2AD317E3658D2938931207AA66
|     	EDB-ID:42745	7.5	https://vulners.com/exploitdb/EDB-ID:42745	*EXPLOIT*
|     	EDB-ID:40961	7.5	https://vulners.com/exploitdb/EDB-ID:40961	*EXPLOIT*
|     	CVE-2024-47252	7.5	https://vulners.com/cve/CVE-2024-47252
|     	CVE-2024-43394	7.5	https://vulners.com/cve/CVE-2024-43394
|     	CVE-2024-43204	7.5	https://vulners.com/cve/CVE-2024-43204
|     	CVE-2024-42516	7.5	https://vulners.com/cve/CVE-2024-42516
|     	CVE-2024-39573	7.5	https://vulners.com/cve/CVE-2024-39573
|     	CVE-2024-38477	7.5	https://vulners.com/cve/CVE-2024-38477
|     	CVE-2024-38472	7.5	https://vulners.com/cve/CVE-2024-38472
|     	CVE-2023-31122	7.5	https://vulners.com/cve/CVE-2023-31122
|     	CVE-2022-30556	7.5	https://vulners.com/cve/CVE-2022-30556
|     	CVE-2022-29404	7.5	https://vulners.com/cve/CVE-2022-29404
|     	CVE-2022-26377	7.5	https://vulners.com/cve/CVE-2022-26377
|     	CVE-2022-22719	7.5	https://vulners.com/cve/CVE-2022-22719
|     	CVE-2021-34798	7.5	https://vulners.com/cve/CVE-2021-34798
|     	CVE-2021-33193	7.5	https://vulners.com/cve/CVE-2021-33193
|     	CVE-2021-26690	7.5	https://vulners.com/cve/CVE-2021-26690
|     	CVE-2019-0217	7.5	https://vulners.com/cve/CVE-2019-0217
|     	CVE-2018-8011	7.5	https://vulners.com/cve/CVE-2018-8011
|     	CVE-2018-17199	7.5	https://vulners.com/cve/CVE-2018-17199
|     	CVE-2018-1303	7.5	https://vulners.com/cve/CVE-2018-1303
|     	CVE-2017-9798	7.5	https://vulners.com/cve/CVE-2017-9798
|     	CVE-2017-15710	7.5	https://vulners.com/cve/CVE-2017-15710
|     	CVE-2016-8743	7.5	https://vulners.com/cve/CVE-2016-8743
|     	CVE-2016-2161	7.5	https://vulners.com/cve/CVE-2016-2161
|     	CVE-2016-0736	7.5	https://vulners.com/cve/CVE-2016-0736
|     	CVE-2006-20001	7.5	https://vulners.com/cve/CVE-2006-20001
|     	CNVD-2025-16614	7.5	https://vulners.com/cnvd/CNVD-2025-16614
|     	CNVD-2025-16613	7.5	https://vulners.com/cnvd/CNVD-2025-16613
|     	CNVD-2025-16612	7.5	https://vulners.com/cnvd/CNVD-2025-16612
|     	CNVD-2025-16609	7.5	https://vulners.com/cnvd/CNVD-2025-16609
|     	CNVD-2024-36393	7.5	https://vulners.com/cnvd/CNVD-2024-36393
|     	CNVD-2024-36390	7.5	https://vulners.com/cnvd/CNVD-2024-36390
|     	CNVD-2024-36389	7.5	https://vulners.com/cnvd/CNVD-2024-36389
|     	CNVD-2024-20839	7.5	https://vulners.com/cnvd/CNVD-2024-20839
|     	CNVD-2023-93320	7.5	https://vulners.com/cnvd/CNVD-2023-93320
|     	CNVD-2023-80558	7.5	https://vulners.com/cnvd/CNVD-2023-80558
|     	CNVD-2022-53584	7.5	https://vulners.com/cnvd/CNVD-2022-53584
|     	CNVD-2022-51058	7.5	https://vulners.com/cnvd/CNVD-2022-51058
|     	CNVD-2022-41639	7.5	https://vulners.com/cnvd/CNVD-2022-41639
|     	CNVD-2022-13199	7.5	https://vulners.com/cnvd/CNVD-2022-13199
|     	CNVD-2022-03223	7.5	https://vulners.com/cnvd/CNVD-2022-03223
|     	CNVD-2019-41283	7.5	https://vulners.com/cnvd/CNVD-2019-41283
|     	CNVD-2019-08945	7.5	https://vulners.com/cnvd/CNVD-2019-08945
|     	CNVD-2017-13906	7.5	https://vulners.com/cnvd/CNVD-2017-13906
|     	CNVD-2016-13233	7.5	https://vulners.com/cnvd/CNVD-2016-13233
|     	CNVD-2016-13232	7.5	https://vulners.com/cnvd/CNVD-2016-13232
|     	CDC791CD-A414-5ABE-A897-7CFA3C2D3D29	7.5	https://vulners.com/githubexploit/CDC791CD-A414-5ABE-A897-7CFA3C2D3D29	*EXPLOIT*
|     	A0F268C8-7319-5637-82F7-8DAF72D14629	7.5	https://vulners.com/githubexploit/A0F268C8-7319-5637-82F7-8DAF72D14629	*EXPLOIT*
|     	56EC26AF-7FB6-5CF0-B179-6151B1D53BA5	7.5	https://vulners.com/githubexploit/56EC26AF-7FB6-5CF0-B179-6151B1D53BA5	*EXPLOIT*
|     	45D138AD-BEC6-552A-91EA-8816914CA7F4	7.5	https://vulners.com/githubexploit/45D138AD-BEC6-552A-91EA-8816914CA7F4	*EXPLOIT*
|     	CVE-2025-49812	7.4	https://vulners.com/cve/CVE-2025-49812
|     	HTTPD:D66D5F45690EBE82B48CC81EF6388EE8	7.3	https://vulners.com/httpd/HTTPD:D66D5F45690EBE82B48CC81EF6388EE8
|     	CVE-2023-38709	7.3	https://vulners.com/cve/CVE-2023-38709
|     	CVE-2020-35452	7.3	https://vulners.com/cve/CVE-2020-35452
|     	CNVD-2024-36395	7.3	https://vulners.com/cnvd/CNVD-2024-36395
|     	PACKETSTORM:127546	6.8	https://vulners.com/packetstorm/PACKETSTORM:127546	*EXPLOIT*
|     	HTTPD:3EDB21E49474605400D2476536BB9C24	6.8	https://vulners.com/httpd/HTTPD:3EDB21E49474605400D2476536BB9C24
|     	CVE-2014-0226	6.8	https://vulners.com/cve/CVE-2014-0226
|     	1337DAY-ID-22451	6.8	https://vulners.com/zdt/1337DAY-ID-22451	*EXPLOIT*
|     	CVE-2024-24795	6.3	https://vulners.com/cve/CVE-2024-24795
|     	CNVD-2024-36394	6.3	https://vulners.com/cnvd/CNVD-2024-36394
|     	HTTPD:E3E8BE7E36621C4506552BA051ECC3C8	6.1	https://vulners.com/httpd/HTTPD:E3E8BE7E36621C4506552BA051ECC3C8
|     	HTTPD:8DF9389A321028B4475CE2E9B5BFC7A6	6.1	https://vulners.com/httpd/HTTPD:8DF9389A321028B4475CE2E9B5BFC7A6
|     	HTTPD:5FF2D6B51D8115FFCB653949D8D36345	6.1	https://vulners.com/httpd/HTTPD:5FF2D6B51D8115FFCB653949D8D36345
|     	HTTPD:503FD99BD66D7A2A870F8608BC17CE57	6.1	https://vulners.com/httpd/HTTPD:503FD99BD66D7A2A870F8608BC17CE57
|     	CVE-2020-1927	6.1	https://vulners.com/cve/CVE-2020-1927
|     	CVE-2019-10098	6.1	https://vulners.com/cve/CVE-2019-10098
|     	CVE-2019-10092	6.1	https://vulners.com/cve/CVE-2019-10092
|     	CVE-2016-4975	6.1	https://vulners.com/cve/CVE-2016-4975
|     	CNVD-2020-21904	6.1	https://vulners.com/cnvd/CNVD-2020-21904
|     	CAB023BA-58A3-5C35-BF97-F9C43133DB5E	6.1	https://vulners.com/gitee/CAB023BA-58A3-5C35-BF97-F9C43133DB5E	*EXPLOIT*
|     	4013EC74-B3C1-5D95-938A-54197A58586D	6.1	https://vulners.com/githubexploit/4013EC74-B3C1-5D95-938A-54197A58586D	*EXPLOIT*
|     	HTTPD:5C83890838E7C6903630B41EC3F2540D	5.9	https://vulners.com/httpd/HTTPD:5C83890838E7C6903630B41EC3F2540D
|     	CVE-2018-1302	5.9	https://vulners.com/cve/CVE-2018-1302
|     	CVE-2018-1301	5.9	https://vulners.com/cve/CVE-2018-1301
|     	CNVD-2018-06536	5.9	https://vulners.com/cnvd/CNVD-2018-06536
|     	CNVD-2018-06535	5.9	https://vulners.com/cnvd/CNVD-2018-06535
|     	1337DAY-ID-33577	5.8	https://vulners.com/zdt/1337DAY-ID-33577	*EXPLOIT*
|     	HTTPD:B900BFA5C32A54AB9D565F59C8AC1D05	5.5	https://vulners.com/httpd/HTTPD:B900BFA5C32A54AB9D565F59C8AC1D05
|     	CVE-2020-13938	5.5	https://vulners.com/cve/CVE-2020-13938
|     	CNVD-2021-44765	5.5	https://vulners.com/cnvd/CNVD-2021-44765
|     	HTTPD:FCCF5DB14D66FA54B47C34D9680C0335	5.3	https://vulners.com/httpd/HTTPD:FCCF5DB14D66FA54B47C34D9680C0335
|     	HTTPD:EB26BC6B6E566C865F53A311FC1A6744	5.3	https://vulners.com/httpd/HTTPD:EB26BC6B6E566C865F53A311FC1A6744
|     	HTTPD:BAAB4065D254D64A717E8A5C847C7BCA	5.3	https://vulners.com/httpd/HTTPD:BAAB4065D254D64A717E8A5C847C7BCA
|     	HTTPD:8806CE4EFAA6A567C7FAD62778B6A46F	5.3	https://vulners.com/httpd/HTTPD:8806CE4EFAA6A567C7FAD62778B6A46F
|     	HTTPD:85F5649E5C2D697DCF21420D622C618E	5.3	https://vulners.com/httpd/HTTPD:85F5649E5C2D697DCF21420D622C618E
|     	HTTPD:5C8B0394DE17D1C29719B16CE00F475D	5.3	https://vulners.com/httpd/HTTPD:5C8B0394DE17D1C29719B16CE00F475D
|     	HTTPD:25716876F18D7575B7A8778A4476ED9E	5.3	https://vulners.com/httpd/HTTPD:25716876F18D7575B7A8778A4476ED9E
|     	CVE-2022-37436	5.3	https://vulners.com/cve/CVE-2022-37436
|     	CVE-2022-28614	5.3	https://vulners.com/cve/CVE-2022-28614
|     	CVE-2022-28330	5.3	https://vulners.com/cve/CVE-2022-28330
|     	CVE-2020-1934	5.3	https://vulners.com/cve/CVE-2020-1934
|     	CVE-2020-11985	5.3	https://vulners.com/cve/CVE-2020-11985
|     	CVE-2019-17567	5.3	https://vulners.com/cve/CVE-2019-17567
|     	CVE-2019-0220	5.3	https://vulners.com/cve/CVE-2019-0220
|     	CVE-2018-1283	5.3	https://vulners.com/cve/CVE-2018-1283
|     	CNVD-2023-30859	5.3	https://vulners.com/cnvd/CNVD-2023-30859
|     	CNVD-2022-53582	5.3	https://vulners.com/cnvd/CNVD-2022-53582
|     	CNVD-2022-51059	5.3	https://vulners.com/cnvd/CNVD-2022-51059
|     	CNVD-2021-44766	5.3	https://vulners.com/cnvd/CNVD-2021-44766
|     	CNVD-2020-46278	5.3	https://vulners.com/cnvd/CNVD-2020-46278
|     	CNVD-2020-29872	5.3	https://vulners.com/cnvd/CNVD-2020-29872
|     	CNVD-2019-08941	5.3	https://vulners.com/cnvd/CNVD-2019-08941
|     	SSV:96537	5.0	https://vulners.com/seebug/SSV:96537	*EXPLOIT*
|     	SSV:62058	5.0	https://vulners.com/seebug/SSV:62058	*EXPLOIT*
|     	SSV:61874	5.0	https://vulners.com/seebug/SSV:61874	*EXPLOIT*
|     	HTTPD:F8C8FF58A7154D4AEB884460782E6943	5.0	https://vulners.com/httpd/HTTPD:F8C8FF58A7154D4AEB884460782E6943
|     	HTTPD:EA40955F0C4A208F0F1841F397D60CF3	5.0	https://vulners.com/httpd/HTTPD:EA40955F0C4A208F0F1841F397D60CF3
|     	HTTPD:E07AEA8765BD0F6E15AAD496A2714564	5.0	https://vulners.com/httpd/HTTPD:E07AEA8765BD0F6E15AAD496A2714564
|     	HTTPD:A158A6C24B676357DB136BEF8DE76E9B	5.0	https://vulners.com/httpd/HTTPD:A158A6C24B676357DB136BEF8DE76E9B
|     	HTTPD:867B7FEBC94AAFD9542C6BE363C3D8A3	5.0	https://vulners.com/httpd/HTTPD:867B7FEBC94AAFD9542C6BE363C3D8A3
|     	HTTPD:37A2DAF62C74FA5777EC2F97F085C496	5.0	https://vulners.com/httpd/HTTPD:37A2DAF62C74FA5777EC2F97F085C496
|     	HTTPD:3353898BFE39BBDF8391739FC2DDB5B1	5.0	https://vulners.com/httpd/HTTPD:3353898BFE39BBDF8391739FC2DDB5B1
|     	HTTPD:30E31E412AB4505FEE1161AB62A2E9AD	5.0	https://vulners.com/httpd/HTTPD:30E31E412AB4505FEE1161AB62A2E9AD
|     	EXPLOITPACK:DAED9B9E8D259B28BF72FC7FDC4755A7	5.0	https://vulners.com/exploitpack/EXPLOITPACK:DAED9B9E8D259B28BF72FC7FDC4755A7	*EXPLOIT*
|     	EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D	5.0	https://vulners.com/exploitpack/EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D	*EXPLOIT*
|     	CVE-2015-3183	5.0	https://vulners.com/cve/CVE-2015-3183
|     	CVE-2015-0228	5.0	https://vulners.com/cve/CVE-2015-0228
|     	CVE-2014-3581	5.0	https://vulners.com/cve/CVE-2014-3581
|     	CVE-2014-3523	5.0	https://vulners.com/cve/CVE-2014-3523
|     	CVE-2014-0231	5.0	https://vulners.com/cve/CVE-2014-0231
|     	CVE-2014-0098	5.0	https://vulners.com/cve/CVE-2014-0098
|     	CVE-2013-6438	5.0	https://vulners.com/cve/CVE-2013-6438
|     	CVE-2013-5704	5.0	https://vulners.com/cve/CVE-2013-5704
|     	CNVD-2015-01691	5.0	https://vulners.com/cnvd/CNVD-2015-01691
|     	1337DAY-ID-28573	5.0	https://vulners.com/zdt/1337DAY-ID-28573	*EXPLOIT*
|     	1337DAY-ID-26574	5.0	https://vulners.com/zdt/1337DAY-ID-26574	*EXPLOIT*
|     	SSV:87152	4.3	https://vulners.com/seebug/SSV:87152	*EXPLOIT*
|     	PACKETSTORM:127563	4.3	https://vulners.com/packetstorm/PACKETSTORM:127563	*EXPLOIT*
|     	HTTPD:C42F64A6857578ED72E18211FDE568E0	4.3	https://vulners.com/httpd/HTTPD:C42F64A6857578ED72E18211FDE568E0
|     	HTTPD:883E996A34F70F5DF670D81697321AAB	4.3	https://vulners.com/httpd/HTTPD:883E996A34F70F5DF670D81697321AAB
|     	HTTPD:7BB4E1B5FF441B7BE1E27DCB50A9280A	4.3	https://vulners.com/httpd/HTTPD:7BB4E1B5FF441B7BE1E27DCB50A9280A
|     	HTTPD:45932C372ED0E0588A3AE5126126F55B	4.3	https://vulners.com/httpd/HTTPD:45932C372ED0E0588A3AE5126126F55B
|     	CVE-2016-8612	4.3	https://vulners.com/cve/CVE-2016-8612
|     	CVE-2015-3185	4.3	https://vulners.com/cve/CVE-2015-3185
|     	CVE-2014-8109	4.3	https://vulners.com/cve/CVE-2014-8109
|     	CVE-2014-0118	4.3	https://vulners.com/cve/CVE-2014-0118
|     	CVE-2014-0117	4.3	https://vulners.com/cve/CVE-2014-0117
|     	1337DAY-ID-33575	4.3	https://vulners.com/zdt/1337DAY-ID-33575	*EXPLOIT*
|_    	PACKETSTORM:140265	0.0	https://vulners.com/packetstorm/PACKETSTORM:140265	*EXPLOIT*
| http-sql-injection: 
|   Possible sqli for queries:
|     http://192.168.56.3:80/?C=N%3BO%3DD%27%20OR%20sqlspider
|     http://192.168.56.3:80/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.56.3:80/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.56.3:80/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.56.3:80/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.56.3:80/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.56.3:80/?C=D%3BO%3DA%27%20OR%20sqlspider
|_    http://192.168.56.3:80/?C=N%3BO%3DA%27%20OR%20sqlspider
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
445/tcp  open   netbios-ssn syn-ack      Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
631/tcp  open   ipp         syn-ack      CUPS 1.7
|_http-server-header: CUPS/1.7 IPP/2.1
| vulners: 
|   cpe:/a:apple:cups:1.7: 
|     	CVE-2014-5031	5.0	https://vulners.com/cve/CVE-2014-5031
|     	CVE-2014-2856	4.3	https://vulners.com/cve/CVE-2014-2856
|     	CVE-2014-5030	1.9	https://vulners.com/cve/CVE-2014-5030
|     	CVE-2014-3537	1.2	https://vulners.com/cve/CVE-2014-3537
|_    	CVE-2013-6891	1.2	https://vulners.com/cve/CVE-2013-6891
3000/tcp closed ppp         conn-refused
3306/tcp open   mysql       syn-ack      MySQL (unauthorized)
8080/tcp open   http        syn-ack      Jetty 8.1.7.v20120910
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.56.3
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.56.3:8080/continuum/security/login.action;jsessionid=1cmt4n3t4aeddze9qubewsbn0
|     Form id: loginform
|     Form action: /continuum/security/login_submit.action;jsessionid=1cmt4n3t4aeddze9qubewsbn0
|     
|     Path: http://192.168.56.3:8080/continuum/security/login.action;jsessionid=1cmt4n3t4aeddze9qubewsbn0
|     Form id: loginform
|     Form action: /continuum/security/login_submit.action;jsessionid=1cmt4n3t4aeddze9qubewsbn0
|     
|     Path: http://192.168.56.3:8080/continuum/security/login_submit.action;jsessionid=1cmt4n3t4aeddze9qubewsbn0
|     Form id: loginform
|     Form action: /continuum/security/login_submit.action;jsessionid=1cmt4n3t4aeddze9qubewsbn0
|     
|     Path: http://192.168.56.3:8080/continuum/security/register.action;jsessionid=1cmt4n3t4aeddze9qubewsbn0
|     Form id: registerform
|     Form action: /continuum/security/register_submit.action;jsessionid=1cmt4n3t4aeddze9qubewsbn0
|     
|     Path: http://192.168.56.3:8080/continuum/security/passwordReset.action;jsessionid=1cmt4n3t4aeddze9qubewsbn0
|     Form id: passwordresetform
|     Form action: /continuum/security/passwordReset_submit.action;jsessionid=1cmt4n3t4aeddze9qubewsbn0
|     
|     Path: http://192.168.56.3:8080/continuum/security/login.action;jsessionid=1cmt4n3t4aeddze9qubewsbn0
|     Form id: loginform
|     Form action: /continuum/security/login_submit.action;jsessionid=1cmt4n3t4aeddze9qubewsbn0
|     
|     Path: http://192.168.56.3:8080/continuum/security/login.action;jsessionid=1cmt4n3t4aeddze9qubewsbn0
|     Form id: loginform
|     Form action: /continuum/security/login_submit.action;jsessionid=1cmt4n3t4aeddze9qubewsbn0
|     
|     Path: http://192.168.56.3:8080/continuum/security/register_submit.action;jsessionid=1cmt4n3t4aeddze9qubewsbn0
|     Form id: registerform
|     Form action: /continuum/security/register_submit.action;jsessionid=1cmt4n3t4aeddze9qubewsbn0
|     
|     Path: http://192.168.56.3:8080/continuum/security/passwordReset_submit.action;jsessionid=1cmt4n3t4aeddze9qubewsbn0
|     Form id: passwordresetform
|_    Form action: /continuum/security/passwordReset_submit.action;jsessionid=1cmt4n3t4aeddze9qubewsbn0
|_http-server-header: Jetty(8.1.7.v20120910)
8181/tcp closed intermapper conn-refused
Service Info: Hosts: 127.0.0.1, UBUNTU; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-vuln-regsvc-dos: 
|   VULNERABLE:
|   Service regsvc in Microsoft Windows systems vulnerable to denial of service
|     State: VULNERABLE
|       The service regsvc in Microsoft Windows 2000 systems is vulnerable to denial of service caused by a null deference
|       pointer. This script will crash the service if it is vulnerable. This vulnerability was discovered by Ron Bowes
|       while working on smb-enum-sessions.
|_          
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: false

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Oct 22 20:54:32 2025 -- 1 IP address (1 host up) scanned in 334.08 seconds
