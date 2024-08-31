
# Malware Model: Indirect Syscalls for EDR Evasion

This repository demonstrates a malware model leveraging Indirect Syscalls to evade Endpoint Detection and Response (EDR) systems. The malware is crafted using C and Assembly, focusing on evading traditional security mechanisms that detect Native API or standard system calls.

## Features

- **Indirect Syscalls**: Circumvents conventional EDR detections by avoiding direct Native API or standard syscall methods, which are typically monitored.
- **EDR Evasion**: Uses Indirect Syscalls to execute system functions without triggering common security detections, enhancing stealth and avoiding API call monitoring.

## Technical Overview

### 1. Indirect Syscalls Implementation
- **Syscall Invocation**: The malware invokes syscalls indirectly by writing each Native API function in Assembly, retrieving the System Service Number (SSN) of the WinAPI function, placing it in the EAX register, and jumping to the address of the syscall instruction in memory instead of using a direct syscall assembly instruction.
- **Bypassing EDR**: By not relying on the usual API, the malware avoids detection mechanisms that monitor Native API calls.

### 2. Development Process
- **C and Assembly**: The malware is developed using a combination of C for higher-level logic and Assembly for low-level syscall invocation.
- **Syscall Table**: Utilizes a custom syscall table to map and invoke specific system functions indirectly.

## Usage

1. **Clone the Repository**: Download the project from GitHub.
2. **Compile the Code**: Use Visual Studio or a compatible compiler to build the executable.
3. **Run the Malware**: Execute the compiled binary, optionally specifying a process ID (PID) and thread ID (TID) for injection.

    ```bash
    IndirectSyscall.exe <PID> <TID>
    ```

### Prerequisites

- **Disable Windows Defender**: Ensure Just-In-Time (JIT) Windows Defender is disabled to avoid interference during execution.
- **Administrator Privileges**: Running the malware may require administrator rights depending on the target system and operations performed.

## Disclaimer

This project is for educational purposes only. Misuse of this code can lead to severe consequences, and it should only be used in a controlled, legal environment.

## License

All rights reserved.
