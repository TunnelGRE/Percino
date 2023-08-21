# Augustus
Evasive Golang Loader


Augustus is a Golang loader designed for a secure execution of shellcode utilizing the process hollowing technique with anti-sandbox and anti-analysis measures. 
The shellcode is encrypted with the Triple DES (3DES) encryption algorithm.

Full EDR bypass with any C2 Framework. Tested with Cobalt Strike against MDE EDR.


Key Features:
- 3DES Encryption
- Sandbox Evasion
- Analysis Evasion
- Process Hollowing



I provide a light version without sandbox & analysis evasion because the compiled version is very heavy. TIP: use a packer to compress better.
