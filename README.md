MIAX protocol dissector for Wireshark


Find the path in the _About->Folders->Personal LUA Plugins_
In Linux it can be `/home/$USER/.local/lib/wireshark/plugins`
Creeate a hard link to the LUA script
```
mkdir -p /home/$USER/.local/lib/wireshark/plugins
ln  miax.lua /home/$USER/.local/lib/wireshark/plugins/miax.lua
```

If needed enable LUA support in _Edit->Preferences->Lua_. In the _About->Plugins_ look for `miax`. Reload the plugin _Analyze->Relaod LUA Plugins_.




