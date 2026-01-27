```mermaid
flowchart TD
    A[Start ScriptVersion 1.5] --> B[Initialize Variables Logging]
    B --> C[Check Admin Role]
    C -->|Not Admin| C1[Exit 0Insufficient Privileges]
    C -->|Admin| D[Check Last RunInterval]
    D -->|Less than 6 days| D1[Exit 2Too Soon]
    D -->|More than 6 days| E[Test Prerequisites]
    E --> F{PrerequisiteCheckSuccessful?}
    F -->|Yes| G[Skip to Registry Check]
    F -->|No| H[Check Secure Boot Status]
    H -->|Disabled| H1[Exit 0Secure Boot Disabled]
    H -->|Enabled| I[Check BitLocker Info]
    I --> J[Check BitLockerRecovery Key]
    J -->|Missing| J1[Exit 0No Recovery Key]
    J -->|Present| K[Get Device InformationManufacturer, Model, BIOS]
    K --> L[Normalize Vendor NameDell, HP, Fujitsu, etc.]
    L --> M{BIOS CSV FileExists?}
    M -->|No| N[Download CSVfrom Repository]
    M -->|Yes| O[Import CSV]
    N --> O
    O --> P[Extract Clean BIOSVersion String]
    P --> Q{Device BIOS greater equal Minimum Required?}
    Q -->|No| Q1[Exit 0BIOS Update Required]
    Q -->|Yes| R[Set PrerequisiteCheck = 1]
    R --> G[Check Registry Keys]
    G --> S[Check AvailableUpdatesRegistry Key]
    S --> T[Check WindowsUEFICA2023CapableRegistry Key]
    T --> U[Check MicrosoftUpdateManagedOptInRegistry Key]
    
    U --> V[Get UEFI CertificatesPK, KEK, DB]
    
    V --> V1[Check Platform KeyPK Certificates]
    V1 --> V2[Check Key Exchange KeyKEK Certificates]
    
    V2 --> V3{KEK UpdateStatus?}
    V3 -->|Old Only| V3A[BIOS Update Required]
    V3 -->|Old + New| V3B[Certificate Updated]
    V3 -->|New Only| V3C[Latest]
    
    V3A --> W[Get DB Certificates]
    V3B --> W
    V3C --> W
    
    W --> W1[Check WindowsProduction PCA 2011]
    W1 --> W2[Check WindowsUEFI CA 2023]
    
    W2 --> X[Check 3rd PartyUEFI CA Certificates]
    X --> Y[Check Option ROMUEFI CA Certificates]
    
    Y --> Z[Mount UEFI Partition]
    
    Z --> Z1[Check Boot LoaderCertificate Signatures]
    Z1 --> Z2[bootmgfw.efi]
    Z2 --> Z3[bootmgr.efi]
    Z3 --> Z4[bootx64.efi]
    Z4 --> Z5[SecureBootRecovery.efi]
    Z5 --> Z6[winload.efi]
    Z6 --> Z7[winload.exe]
    Z7 --> Z8[ntoskrnl.exe]
    Z8 --> Z9[Unmount UEFI Partition]
    Z9 --> AA[Get System Event LogSecure Boot Events]
    AA --> AB{All RequiredCertificatesPresent?}
    AB -->|Minimum Only| AB1[Exit Code 0Minimum Certs OK]
    AB -->|All Including 3rd Party| AB2[Exit Code 2All Certs OK]
    AB -->|Missing| AB3[Exit Code 1Missing Certs]
    AB1 --> AC[Write Debug Info]
    AB2 --> AC
    AB3 --> AC
    AC --> AD[Stop Transcript]
    AD --> AE[End Script]
    C1 --> AE
    D1 --> AE
    H1 --> AE
    J1 --> AE
    Q1 --> AE
    AE --> AF[Exit with Code]
    ```