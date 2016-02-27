[Secret Net 7](http://www.securitycode.ru/products/secret_net) and [Secret Net Studio 8](http://www.securitycode.ru/products/secret-net-studio) local privileges escalation exploit.

0day vulnerabilities in sncc0.sys kernel driver of Secrity Code products allows attacker to perform local privileges escalation from Guest to Local System. Also, attacker that has access to any Windows system may manually install sncc0.sys (that has valid digital signature from Security Code) and exploit it's vulnerability to bypass DSE and load unsigned kernel mode drivers on Windows x64 platforms.

For detailed vulnerability analysis and explanation of how sncc0_00220010_expl code works please read Windows DSE bypass part of my article "[Exploiting SMM callout vulnerabilities in Lenovo firmware](http://blog.cr4.sh/2016/02/exploiting-smm-callout-vulnerabilities.html)".

This exploit was tested with 64-bit versions of Windows 7, 8, 8.1 and 10. On SMEP enabled systems you have to manually restore original value of CR4 register to avoid PatchGuard bugchecks, for real life usage example please check my [fwexpl](https://github.com/Cr4sh/fwexpl) project.

Using exploit with Secret Net 7.4.577.0:

<img src="https://raw.githubusercontent.com/Cr4sh/secretnet_expl/43a1289ec96e880708ccc7150a42275ff8c1e02e/secretnet-7.4.png" width="600" />

Secret Net Studio 8.0.616.0 beta (currently I'm not able to test my exploit with the most recent version because vendor removed Secret Net Studio from Downloads page):

<img src="https://raw.githubusercontent.com/Cr4sh/secretnet_expl/43a1289ec96e880708ccc7150a42275ff8c1e02e/secretnet-studio-8.0.png" width="620" />
