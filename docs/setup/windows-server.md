# Windows Server Setup

## Purpose

The Windows Server 2025 virtual machine provides the core identity and network services for the Project Janus IT environment. It acts as the Active Directory domain controller, DNS server, and DHCP server for the Windows 11 Enterprise endpoint.

## System Information

| Item | Value |
|---|---|
| Operating system | Windows Server 2025 |
| Host role | Domain controller, DNS server, DHCP server |
| IP address | `10.10.10.10/24` |
| Default gateway | `10.10.10.1` |
| Preferred DNS | `127.0.0.1` |
| Domain | `purplelab.local` |
| Network | IT subnet, `10.10.10.0/24` |

## Configuration Summary

The server was assigned a static IPv4 configuration so that domain, DNS, and DHCP services remain available at a consistent address.

Active Directory Domain Services was installed and the server was promoted to a domain controller for `purplelab.local`. A test domain user was created to confirm that accounts could be provisioned and used by the Windows endpoint.

The DHCP service was configured to provide addresses to systems on the IT subnet. The Windows endpoint successfully received an address, default gateway, DNS server, and DNS suffix from the server.

## Validation

The following results confirmed that the server configuration was working:

- The Windows endpoint received `10.10.10.3/24` through DHCP.
- The endpoint received `10.10.10.1` as its default gateway.
- The endpoint received `10.10.10.10` as its DHCP and DNS server.
- The endpoint resolved `purplelab.local` to `10.10.10.10`.
- The endpoint successfully joined the `purplelab.local` domain.
- A domain account successfully authenticated on the endpoint.

## Evidence

Recommended evidence for the repository:

- Static IPv4 configuration screenshot
- DHCP scope screenshot
- Active DHCP lease screenshot
- Active Directory Users and Computers screenshot
- DNS resolution test from the Windows endpoint
- Domain authentication test using `whoami`

Store sanitized screenshots in:

```text
docs/assets/windows-server/
```

## Problems Encountered

Initial issues included configuring DHCP, DNS, and internet access across the internal network. These were resolved through correcting the server network settings, verifying pfSense routing, and confirming that the endpoint used the domain controller for DNS.

## Security Notes

Do not commit:

- Administrator passwords
- Domain-user passwords
- Private keys or certificates
- Unredacted configuration exports
- Screenshots containing real personal information

## Current Limitations

- Only one Windows endpoint is currently joined to the domain.
- The environment is a small lab and does not represent a full enterprise Active Directory deployment.
- Group Policy-based attack and defense testing is planned but not yet fully implemented.

## DHCP Scope

The DHCP scope distributes addresses from `10.10.10.20` through `10.10.10.220` on the IT subnet.

## Remaining Details to Add

- Lease duration
- Exact Windows Server VM resource allocation
- Any DNS forwarder settings
