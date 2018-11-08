# ISA_dns-export
### ISA Project - DNS export by syslog protocol
#### Application usage
##### Execution

Usage of `SOCK_RAW` requires a **sudo** privilege.   

```
sudo ./dns-export [-r file.pcap] [-i interface] [-s syslog-server] [-t seconds]
```  

All parameters are optional but each of them requires an argument.  
>**-r** processes DNS records from **file.pcap**  
**-i** processes DNS records caught on given **interface**  
**-s** is a **syslog server** on which statistics are going to be sent  
**-t** is a time in **seconds** which is a interval of sending statistics to
syslog server  

Forbidden combination of parameters: **-r -i** | **-r -t**  

Program executed without any parameters will redirect user to
application man page.  

If application processes file, it will send statistics to given syslog server
after file is processed otherwise DNS records will be printed to **stdout**.
  
If application listens on given interface, it will send statistics to given 
syslog server periodically each 60 seconds if not specified by **-t** parameter.
DNS records are printed to **stdout** if **SIGUSR1** signal is obtained.  

##### Restrictions

Application processes DNS records only on UDP port and not TCP. Fragmentation is
not implemented.

When listening on interface, application is in loop and can be terminated
only by **SIGINT** signal aka **CTRL^C**, in this case memory is not 
freed completely.

*_Created by Lukáš Kulda (xkulda01@stud.fit.vutbr.cz)_*