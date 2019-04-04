## New Executable plugin

### Description:
This is a plugin for radare2 to enable new executable file format support for r2.

### Plugin installation 
With r2 installed clone the repository to a directory and then run
` make && make install 
`
### Tasks Done
* Check if ne using magic bytes
* Find the phisical address of binary
* Find virtual address of binary
* Retrieve basic binary info for the user

### Tasks to be done
* Section and segment mapping 

### References 
* http://bytepointer.com/resources/win16_ne_exe_format_win3.0.htm
* http://www.fileformat.info/format/exe/corion-ne.htm

