# Augustus
## Evasive Golang Loader



![Augustus](https://github.com/TunnelGRE/Augustus/assets/130594453/966b2764-5d3d-4afb-9dd8-efe96476dced)



Augustus is a Golang loader designed for a secure execution of shellcode utilizing the process hollowing technique with anti-sandbox and anti-analysis measures. 
The shellcode is encrypted with the Triple DES (3DES) encryption algorithm.

Full EDR bypass with any C2 Framework. Tested with Cobalt Strike against MDE EDR.


Key Features:
- 3DES Encryption
- Sandbox Evasion
- Analysis Evasion
- Process Hollowing


TIP: Compile with 'go build -ldflags "-s -w" main.go' because it is so heavy. If you want to be more slim use packer :)

CS:

![CS](https://github.com/TunnelGRE/Augustus/assets/130594453/1bd70e4d-2487-4526-bad0-7d764a395484)





MSF:
![MSF](https://github.com/TunnelGRE/Augustus/assets/130594453/8d3b24bb-224c-4efb-bcc5-819eae7beb6a)



