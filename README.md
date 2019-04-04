## New Executable plugin

### Description:
this is a plugin for radare2 to enable new executable file format support for r2.

### Plugin installation 
with r2 installed Clone the repository to a directory and then run
` make && make install 
`
### Tasks Done
* Check if ne using magic bytes
* find the phisical address of binary
* find virtual address of binary
* retrieve basic binary info for the user

### Tasks to be done
* section and segment mapping 

### References 
* http://bytepointer.com/resources/win16_ne_exe_format_win3.0.htm
* http://www.fileformat.info/format/exe/corion-ne.htm

