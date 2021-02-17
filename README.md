Program to demonstrate the DLSw protocol (RFC 1795) for routing SNA messages over a TCP/IP network 

To build with GCC:
```
gcc -o dlswserver dlswserver.c
```
To build with Microsoft C (Visual Studio command prompt):
```
cl /out:dlswserver.exe dlswserver.c /link ws2_32.lib
```
