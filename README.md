# Secure File System Simulation using C

### Compile Instructions:

```
g++ -o FileSystem FileSystem.cpp md5.cpp FileSystem_main.cpp
```

### Run Instructions:

#### Initialization

```
./FileSystem -i
```
#### Login 

```
./FileSystem
```

**Other notes:
- Cannot create user that already exists
- Cannot create file that already exists
- Cannot read file that does not exist

**Bell-La-Padula Rules:
- No write and append for lower and higher access level
- No read for higher access level

## References

zedwood n.d, C++ md5 function, viewed 23rd August 2023
http://www.zedwood.com/article/cpp-md5-function
