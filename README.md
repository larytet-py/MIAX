MIAX protocol dissector for Wireshark


Find the path in the About->Folders->Personal LUA Plugins
In Linux it can be `/home/$USER/.local/lib/wireshark/plugins`
Creeate link to the LUA script
```
mkdir -p /home/$USER/.local/lib/wireshark/plugins
ln -s miax.lua /home/$USER/.local/lib/wireshark/plugins/miax.lua
```

Enable LUA support in Edit->Preferences->Lua


