Driver challenge

run.bat will execute all stages of the challenge as expected.

Todo:

Use manual map or process hollowing to hide a cheat usermode application against anti cheat. Be aware that they can target RWX/RX pages for scans looking
for things like function prologues, strings, imports, constants, etc. Also be aware they can target the process itself for these same scans
and even do an on disk check with a checksum.

You could use also modify an export table of a core system dll to load your hack usermode application, through cffexplorer or another trick. Of course, then
you have a nice section object ready to be scanned by an anti cheat, so unlinking, or remapping to a RX region is your best bet. You should invest in obfucsation and encryption
if you want to have a longer lived usermode application.