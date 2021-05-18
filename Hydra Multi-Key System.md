# Hydra Multi-Key System

### Abstract
Microsoft released the Double Key Encryption System (DKE) in the [middle of 2020](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/announcing-public-preview-of-double-key-encryption-for-microsoft/ba-p/1534451) as a means to provide increased protection for sensitive documents and data stored in the Cloud.

The DKE scheme takes sensitive data and encrypts it under two asymmetric public keys in a preset sequential order. The decryption reverses the order used for encryption by the two asymmetric public keys.

The Hydra Multi-Key System (HMKS) proposed here creates a more efficient variant of the DKE by removing undesirable issues found in the DKE scheme and further enhancing its security as well as the potential processing speed.

### The Use Case For Multiple Keys
Requiring the use of multiple keys in a cryptographic system prevents the lost of control of a single key from impacting the entire cryptographic strength in the system when implemented correctly. One example of use for multiple keys cryptographic system includes custodian based protection of highly sensitive data. Multiple Key Cryptographic Systems (MKCS) also takes into consideration the seperation of keys and their containing and executing hardware in different environments to ensure that the compromise of a single environment or hardware will not lead to the leakage of highly sensitive materials including resisting backdoor implants that are potentially existing on untrusted hardware and environments.

### Microsoft Double Key Encryption Scheme
The Microsoft DKE scheme can be found [here] (https://docs.microsoft.com/en-us/microsoft-365/compliance/double-key-encryption?view=o365-worldwide). In simple terms, you have two storage locations for two asymmetric cryptographic keys of the same bit lengths and same key algorithm type. You designate which asymmetric keys to encrypt under in a sequential order and you encrypt your data under that sequential order of asymmetric keys. The decryption routine reverses the sequential order by requiring decryption on the last asymmetric key used to encrypt your document first.

<sub>Note: The File Encryption Key used for encrypting the file content will be the target for the asymmetric keys' encryption.</sub>

### Hydra Multi-Key System Scheme
The HMKS system does not rely on a specific order of execution for the asymmetric key encryption phase. In fact, the encryption and decryption phases are done in parallel rather than in sequence.

The HMKS system requires the following steps to be observed during the Encryption phase:
1.	Generate a Message Crypto Seed (MCS) of sufficient length (~ 512 bits) to be used as a random seed for further deterministic encryption procedures.
2.	Splitting the MCS in equal halves (each ~256 bits) whereby each MCS halves are to be encrypted by each of the asymmetric keys. The MCS halves are called KEK Halves and the splitting order must be noted. Both KEK Halves are issued to both asymmetric keys to be encrypted in parallel.
3.	The KEK Halves are stored in a document typically in the header segment.
4.	The MCS is permutated using a secure pseudo-random function (i.e. SHA-256 secure hash) to generate the sufficient key length for the File Encryption Key. If a keystream is required, a keystream generator could be used with the MCS as the seed for the keystream generator to encrypt the content.
5.	After encrypting the document or sensitive data, the keystream or File Encryption Key is secure cleared.

During the HMKS Decryption phase, the HMKS would follow the procedures: 
1.	The KEK Halves are extracted from the document or encrypted data and each halves are sent to their original asymmetric keys that encrypted the KEK Halves. Sending the wrong KEK Halves to the wrong asymmetric key would lead to incorrect MCS.
2.	Once the decrypted KEK Halves arrive, they are assembled by concatenation of the order they were split to form the original MCS.
3.	The same secure psuedo-random function is used on the MCS to process the decryption of the document or sensitive data.

### Differences and Similarities
The DKE and HMKS shares the same intention of protecting sensitive data using multiple keys to reduce the impact of compromised keys from possibly backdoored hardware or execution environments utilizing two or more asymmetric keys as wrapper keys for the sensitive content's File Encryption Key.

The differences of DKE and HMKS can be summarized.

  DKE     |  HMKS
----------|-----------
Sequential asymmetric key encryption | Parallel asymmetric key encryption
Compromise of the first asymmetric key used to encrypt File Encryption Key breaks the system | Compromise of any asymmetric key but not all the keys will still remain secure
Direct encryption scheme using lesser steps | Requires controlled pre-encryption procedures like generating and splitting the MCS thus requiring more steps

### Conclusion
The HMKS provides compromise resilience against asymmetric key compromise of any of the asymmetric keys in use and can be executed in parallel which Microsoft's DKE does not fully provide in seperate secure execution environments.




