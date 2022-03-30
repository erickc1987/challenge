sc create cheatdriver binPath=C:\cheat\CheatDriver.sys type=kernel
sc create antiCheatdriver binPath=C:\anticheat\antiCheatDriver.sys type=kernel
sc start cheatDriver
sc start antiCheatdriver
start c:\anticheat\AntiCheatUsermode.exe
start c:\cheat\CheatUsermode.exe                         