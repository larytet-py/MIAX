MIAX protocol dissector for Wireshark


Find the path in the _About->Folders->Personal LUA Plugins_
In Linux it can be `/home/$USER/.local/lib/wireshark/plugins`
Creeate a hard link to the LUA script
```
mkdir -p /home/$USER/.local/lib/wireshark/plugins
ln  esesm.lua /home/$USER/.local/lib/wireshark/plugins/3.6/esesm.lua
```

If needed enable LUA support in _Edit->Preferences->Lua_ or in the `~/.local/lib/wireshark/init.lua` . In the _About->Plugins_ look for `miax`. Reload the plugin _Analyze->Relaod LUA Plugins_.
See _To0ols_LUA_Console_ for debug output.



