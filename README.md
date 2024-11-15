# MIAX protocol dissector for Wireshark

Based on 

```
MIAX Pearl Equities Exchange Extended TCP Session Management (ESesM) Protocol Specification
Revision Date: 06/26/2020
Version 1.0.a
```

Find the path in the _About->Folders->Personal LUA Plugins_
In Linux it can be `/home/$USER/.local/lib/wireshark/plugins`

Creeate a hard link to the LUA script

```
mkdir -p /home/$USER/.local/lib/wireshark/plugins
ln  esesm.lua /home/$USER/.local/lib/wireshark/plugins/3.6/esesm.lua
```

If needed enable LUA support in _Edit->Preferences->Lua_ or in the `~/.local/lib/wireshark/init.lua` . In the _About->Plugins_ look for `ESESM`. Reload the plugin _Analyze->Relaod LUA Plugins_.
See _Tools_LUA_Console_ for debug output.

In the _Analyze->Decode As_ Pick TCP, port 41010, in the current pick ESESM.


## Links

* User manual https://www.miaxglobal.com/sites/default/files/website_file-files/MIAX_Pearl_Equities_User_Manual_October_2022.pdf
* https://www.miaxglobal.com/sites/default/files/2022-05/MIAX_MACH_Protocol_v1_2d_re.pdf
* https://www.miaxglobal.com/sites/default/files/2022-05/MIAX_Emerald_MIAX_MACH_Protocol_v1_2e_re.pdf
* https://www.miaxglobal.com/sites/default/files/job-files/TcpSessionMgmt_eSesM_v1.0.a.updated.pdf
* Wireshark’s Lua API Reference Manual https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html