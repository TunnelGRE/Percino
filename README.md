# Percino
## Evasive Golang Loader



Percino is a Golang loader that execute shellcode utilizing the process hollowing technique with anti-sandbox and anti-analysis measures. 
The shellcode is encrypted with the Triple DES (3DES) encryption algorithm.

Full EDR bypass with any C2 Framework. Tested with Cobalt Strike against MDE EDR.


Key Features:
- 3DES Encryption
- Sandbox Evasion
- Analysis Evasion
- Execution delay
- Process Hollowing


TIP: I recommended to sign the binary with CS

CS:

![CS](https://github.com/TunnelGRE/Augustus/assets/130594453/1bd70e4d-2487-4526-bad0-7d764a395484)





MSF:
![MSF](https://github.com/TunnelGRE/Augustus/assets/130594453/8d3b24bb-224c-4efb-bcc5-819eae7beb6a)



