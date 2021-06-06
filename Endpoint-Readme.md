# Endpoint Usage Guide For HMKS

### Brief Introduction
The Hydra Multi-Key System (HMKS) provides two packages for users to develop their own applications and quickly setup their own HMKS instances.

A development API in the form of the 'HydraConnector' package provides a Java-based API for users to quickly develop Java-based applications for the HMKS.

The 'Endpoint-Client' provides a pre-built, easy to deploy Java application that uses the HydraConnector API to allow setup of a Java Client for discovering HMKS compatible devices / smart cards and perform basic cryptographic functions in an easy to use GUI desktop interface.

### Supported Version
The current document corresponds to version `1.0` of the HydraConnector API and version `1.0` of the protocol formats for HMKS.

### Required Java Version
You will need Java 1.8 and above for the Endpoint-Client to run.

### Building the HydraConnector and Endpoint-Client packages
The source packages in the `src` folder are provided for import into any Java IDE of your own choosing. You will need to create your own Java Project in your chosen Java IDE while importing the `src` folder as the source code folder.

You may use any build tool you desire for building and distributing your HMKS Java projects.

If you intend to contribute to this project, please do not submit your build configurations for pull requests.

This project should be neutral to any project build mechanisms.

### Deploying the Endpoint-Client Java GUI Client
You may build and run your own Java GUI Client from within the Endpoint-Client project using your Java IDE.

Alternatively, a JAR file, `HydraStandaloneClient.jar` has been provided in the Endpoint-Client folder for you to quickly deploy an instance of the Java GUI Client.

You would need to install the HydraApplet to one or more JavaCard smart cards with support for JavaCard 3.0.4 before running the `HydraStandaloneClient.jar` file.

You will need to have the smart cards of USB tokens with the HydraApplet inserted into your computer. You may insert one or more devices but do not remove any of the cards or tokens as the current HydraStandaloneClient is not able to detect and handle removed devices.

You may either double click on the `HydraStandaloneClient.jar` file or use a command line to change directory into the Endpoint-Client folder or any folder with the `HydraStandaloneClient.jar` and run the following command:

`java -jar HydraStandaloneClient.jar`

You should have the GUI window as shown below.

![HydraStandaloneClient GUI Window](/images/HydraStandaloneClient.jpg)

### Viewing Connected Hydra Devices
After launching the HydraStandaloneClient, you may want to view the attached Hydra devices by clicking on the 'Key Management' tab to view the attached Hydra devices.

![HydraStandaloneClient Key Management Window](/images/HSC-KMS.jpg)

### Selecting Connected Hydra Devices And Keys For Activities
The Hydra key names are calculated via performing a SHA-256 hash on the uncompressed ECC public key with ASN.1 header (0x04) followed by a CRC-32 calculation on the initial SHA-256 result of the uncompressed ECC public key with ASN.1 header to create a key fingerprint as well as its key name.

The CRC-32 calculation is used for easy readability to determine if the device or key container containing the ECC keypair may contain the correct key.

By no means should the key name be used to assert if the correct ECC private key is present in the device or key container other than for easy naming and for users to quckly glance at the Key Management tab to make a pretty good guess whether the device or key container has the ECC keys necesary for further operations.

### Encryption Activity
Select the Encryption activity from the Activity dropdown box.

Select a key for encryption for each of `Key #1` and `Key #2` option dropdown boxes. You are encouraged to use two different keys for `Key #1` and `Key #2` to allow the use of multiple keys in the Hydra Multi-Key System scheme which recommends two different keys to ensure that the compromise of one will not affect the security of the other.

You will need to select a file for input  for encryption by clicking on the textbox next to the File Input field.

For selecting an output file, you will first need to click on the textbox for the Folder Output field to select which folder you would like the encrypted output file to be stored then enter a file name and extension into the File Output textbox.

![HydraStandaloneClient Encryption Flow](/images/HSC-Encrypt.jpg)

### Decryption Activity
Select the Decryption activity from the Activity dropdown box.

You will need to select an encrypted file for input for decryption by clicking on the textbox next to the File Input field.

For selecting an output file, you will first need to click on the textbox for the Folder Output field to select which folder you would like the decrypted output file to be stored then enter a file name and extension into the File Output textbox.

Selecting keys for `Key #1` and `Key #2` will have no effect during Decryption Activity.

Note: The devices or keys used during the Encryption Activity phase must be connected / discoverable which can be viewed in the 'Key Management' tab. If the original devices or keys used for the Encryption activity are not found, decryption will fail.


### Re-encryption Activity
Select the Re-encryption activity from the Activity dropdown box.

Select a re-encryption key for for each of `Key #1` and `Key #2` option dropdown boxes. You are encouraged to use two different keys for `Key #1` and `Key #2` to allow the use of multiple keys in the Hydra Multi-Key System scheme which recommends two different keys to ensure that the compromise of one will not affect the security of the other.

You will need to select an encrypted file for input for re-encryption by clicking on the textbox next to the File Input field.

For selecting an output file, you will first need to click on the textbox for the Folder Output field to select which folder you would like the re-encrypted output file to be stored then enter a file name and extension into the File Output textbox.

Note: The devices or keys used during the previous Encryption / Re-encryption Activity phase must be connected / discoverable which can be viewed in the 'Key Management' tab. If the devices or keys used for the previous Encryption / Re-encryption activity are not found, decryption will fail.

![HydraStandaloneClient Re-encryption Flow](/images/HSC-Reencrypt.jpg)

### Encryption Workflow for Client Software
A plaintext file or an already enciphered file maybe encrypted with HMKS providing additional security to the file.

### Decryption Workflow for Client Software
A HMKS encrypted file have a specific header format that denotes the file as a HMKS encrypted format. Decryption can only be performed on a HMKS encrypted file using the correct keys discovered by the HydraStandaloneClient software and viewable via the Key Management tab.

An example is a file encrypted under `Key A - Device A` and `Key D - Device D` must be present in the Key Management tab for a file to be decrypted as the software will parse the header and automatically match the declared public keys in the header to the list of available keys and devices listed in the Key Management tab for decryption activity. 

If the relevant keys and devices are not found, decryption will not proceed.

### Re-encryption Workflow for Client Software
Users may change the encryption keys and devices setup for their HMKS encrypted files as part of key rotation policy or as part of disaster recovery and security compromise recovery procedures whenever they want.

Users must have the HMKS encrypted files requiring re-encryption as well as the keysets and devices they previously used for encrypting or re-encrypting their HMKS encrypted files.

An example is the user first encrypts a file under `Key A - Device A` and `Key D - Device D`. The user later presents `Key A - Device A` and `Key D - Device D` keysets together with new re-encrypting keysets of `Key B - Device B` and `Key C - Device C`. At the end of the re-encryption, the working keysets in use after the successful re-encryption will be `Key B - Device B` and `Key C - Device C` and no longer `Key B - Device B` and `Key C - Device C` for the re-encrypted file.

If the user wants to decrypt the re-encrypted file under `Key B - Device B` and `Key C - Device C`, these keysets and devices must be available for decryption.

If the user wants to further re-encrypted the already re-encrypted file under `Key B - Device B` and `Key C - Device C`, the user must select new keysets and have them present together with `Key B - Device B` and `Key C - Device C` for a successful re-encryption.




