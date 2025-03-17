Dump metadata runtime.
Automatically checks the sanity signature.
Also checks if the version bytes is mangled due to xor decryption on access, if its mangled attemps to patch the metadata from version 24 to 31

Made this because im too lazy to do it on Frida typeshit
> [!Note]
> Wacky code, but it works 💀
> 
> Not sure but sometimes it prints the wrong size despite dumping the correct size

# Global Metadata Dumper

**Global Metadata Dumper** is a C++ utility designed to extract global metadata from running processes, particularly those utilizing the IL2CPP framework. This tool offers several key features to ensure accurate and efficient metadata extraction:

## Features

- **Runtime Metadata Dumping**: Captures metadata directly from the target process's memory during execution, ensuring the most current data is retrieved.

- **Sanity Signature Verification**: Automatically validates the integrity of the metadata by checking for known sanity signatures, ensuring the data's authenticity and consistency.

- **Version Byte Correction**: Identifies and corrects mangled version bytes that may result from XOR decryption during access. The tool attempts to patch the metadata for versions ranging from 24 to 31, enhancing compatibility and reliability.

- **Comprehensive Logging**: Provides detailed logs of the dumping process, including any anomalies or corrections made, offering transparency and aiding in troubleshooting.

- **User-Friendly Interface**: Designed with a straightforward command-line interface, making it accessible for both novice and experienced users.

## Known Quirks

While **Global Metadata Dumper** is effective in extracting metadata, users may occasionally notice discrepancies in the reported metadata size. The tool might print an incorrect size despite successfully dumping the correct amount of data. This behavior does not affect the integrity of the dumped metadata but is an area identified for future improvement.

## Usage

To utilize the tool, execute the following command in your terminal:

```
global-metadata-dumper.exe <TargetProcessName>
```

Replace `<TargetProcessName>` with the name of the process from which you intend to dump the metadata.

