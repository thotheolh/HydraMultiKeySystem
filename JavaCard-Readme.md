# JavaCard Applet for Hdyra Multi-Key System

### AID
- Package AID: 48 59 44 52 41
- Applet AID : 48 59 44 52 41 30 31 30 30

### JCVM
- JCVM 3.0.4

### Transient Memory Blocks
1.	JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, 65 bytes 

### Algorithms
1.	KeyAgreement.ALG_EC_SVDP_DH_PLAIN
2.	Cipher.ALG_AES_BLOCK_128_ECB_NOPAD

### Key Types
1.	KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_256
2.	KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256
3.	KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, KeyBuilder.LENGTH_EC_FP_256
4.	KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256

### Installation
A 'HydraAplet.cap' file is available in the 'JavaCard-Applet' folder with source code in the 'src' folder.

### APDU Commands
-	Get Public Key
	-	Input:
		-	CLA: B0   (Reserved Class)
		- 	INS: CA   (GET)
		-	P1:  0x00
		-	P2:  0x00
		-	LC:  0x00 (No Data)
		-	LE:  0x41
		
	-	Output:
		-	SW:  0x9000
		-	65 bytes of uncompressed ECC-SECP256R1 public key of the card
		
-	PSO:DECRYPT/RECRYPT
	-	Input:
		-	CLA: B0   (Reserved Class)
		- 	INS: 2A   (PSO)
		-	P1:  0x01 (DECRYPT) or 0x02 (RECRYPT)
		-	P2:  0x04 (MessageDigest.ALG_SHA256)
		-	LC:  0x63 to 0x83 (99 to 131 bytes)
		-	LE:  LC   (Same as LC)
		
		-	Data:
			-	Version (2 bytes, 0x0100)
			-	Uncompressed Target ECC-SECP256R1 Public Key (65 bytes)
			-	Encrypted Secret (32 to 64 bytes length of AS-ECB-256 encrypted secret)
		
	-	Output:
		-	SW:  0x9000
		-	Decrypt Data (P1 == 0x01):
			-	Raw decrypted secret
		-	Re-encrypted Data (P1 == 0x02):	
			-	Version (2 bytes, 0x0100)
			-	Uncompressed Ephemeral ECC-SECP256R1 Public Key (65 bytes)
			-	Re-encrypted Secret (32 to 64 bytes length of AS-ECB-256 encrypted secret)		