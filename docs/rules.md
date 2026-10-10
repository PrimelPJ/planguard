# Rules

This file is made by `scripts/rules_doc.py`. Do not edit it by hand.

| ID | Cloud | Severity | Check |
|---|---|---|---|
| [PG001](#pg001) | aws | high | S3 bucket has a public ACL |
| [PG002](#pg002) | aws | high | S3 bucket is not protected by a public access block |
| [PG003](#pg003) | aws | medium | S3 bucket does not keep old versions |
| [PG004](#pg004) | aws | critical | SSH or RDP is open to the whole internet |
| [PG005](#pg005) | aws | high | Every port is open to the whole internet |
| [PG006](#pg006) | aws | high | Database can be reached from the internet |
| [PG007](#pg007) | aws | high | Database storage is not encrypted |
| [PG008](#pg008) | aws | medium | Disk is not encrypted |
| [PG009](#pg009) | aws | critical | IAM policy gives full admin access |
| [PG010](#pg010) | aws | medium | CloudTrail is missing key settings |
| [PG011](#pg011) | aws | medium | Database backups are turned off |
| [PG012](#pg012) | aws | medium | Server does not require IMDSv2 |
| [PG101](#pg101) | azure | high | Storage account allows plain HTTP |
| [PG102](#pg102) | azure | medium | Storage account allows old TLS versions |
| [PG103](#pg103) | azure | high | Storage allows public access to files |
| [PG104](#pg104) | azure | critical | SSH or RDP is open to the whole internet |
| [PG105](#pg105) | azure | medium | Key Vault can be deleted for good right away |
| [PG106](#pg106) | azure | high | SQL server can be reached from the internet |
| [PG107](#pg107) | azure | medium | Linux VM allows password login |

## PG001

**S3 bucket has a public ACL** (aws, high)

- **Why it matters:** Anyone on the internet (or any AWS user) can read the files in this bucket.
- **How to fix:** Set the ACL to private and share files with signed URLs or a bucket policy that names who can read.
- **NIST SP 800-53:** AC-3 (Access Enforcement), SC-7 (Boundary Protection)

## PG002

**S3 bucket is not protected by a public access block** (aws, high)

- **Why it matters:** Without a public access block, one wrong ACL or policy can make the bucket public.
- **How to fix:** Add an aws_s3_bucket_public_access_block for the bucket with all four settings set to true.
- **NIST SP 800-53:** AC-3 (Access Enforcement), SC-7 (Boundary Protection)

## PG003

**S3 bucket does not keep old versions** (aws, medium)

- **Why it matters:** If a file is deleted or overwritten (by mistake or by ransomware), it cannot be brought back.
- **How to fix:** Add aws_s3_bucket_versioning for the bucket with status = "Enabled".
- **NIST SP 800-53:** CP-9 (System Backup)

## PG004

**SSH or RDP is open to the whole internet** (aws, critical)

- **Why it matters:** Bots scan the internet for open SSH and RDP all day and try to guess passwords or use known bugs.
- **How to fix:** Only allow your own IP range, or close the port and use AWS Systems Manager Session Manager.
- **NIST SP 800-53:** SC-7 (Boundary Protection), AC-17 (Remote Access)

## PG005

**Every port is open to the whole internet** (aws, high)

- **Why it matters:** Every service on the server can be reached by anyone, including ones you forgot were running.
- **How to fix:** Only open the ports you need (like 443), and only to the sources that need them.
- **NIST SP 800-53:** SC-7 (Boundary Protection)

## PG006

**Database can be reached from the internet** (aws, high)

- **Why it matters:** The database gets a public address, so attackers can try to log in to it directly.
- **How to fix:** Set publicly_accessible = false and reach the database from inside the VPC.
- **NIST SP 800-53:** SC-7 (Boundary Protection), AC-3 (Access Enforcement)

## PG007

**Database storage is not encrypted** (aws, high)

- **Why it matters:** Anyone who gets a copy of the disk or a snapshot can read the data.
- **How to fix:** Set storage_encrypted = true (this can only be set when the database is created).
- **NIST SP 800-53:** SC-28 (Protection of Information at Rest)

## PG008

**Disk is not encrypted** (aws, medium)

- **Why it matters:** Anyone who gets a copy of the disk or a snapshot can read the data on it.
- **How to fix:** Set encrypted = true on the volume, or turn on EBS encryption by default for the account.
- **NIST SP 800-53:** SC-28 (Protection of Information at Rest)

## PG009

**IAM policy gives full admin access** (aws, critical)

- **Why it matters:** Whoever gets this policy can do anything in the account, including deleting everything.
- **How to fix:** List only the actions and resources the role really needs.
- **NIST SP 800-53:** AC-6 (Least Privilege)

## PG010

**CloudTrail is missing key settings** (aws, medium)

- **Why it matters:** Activity in some regions is not logged, or someone could edit the logs without you knowing.
- **How to fix:** Set is_multi_region_trail = true and enable_log_file_validation = true.
- **NIST SP 800-53:** AU-2 (Event Logging), AU-9 (Protection of Audit Information), AU-12 (Audit Record Generation)

## PG011

**Database backups are turned off** (aws, medium)

- **Why it matters:** If data is lost or corrupted, there is no backup to restore from.
- **How to fix:** Set backup_retention_period to at least 7 days.
- **NIST SP 800-53:** CP-9 (System Backup)

## PG012

**Server does not require IMDSv2** (aws, medium)

- **Why it matters:** A bug in an app on the server can be used to steal the server's AWS keys (this is how the 2019 Capital One breach worked).
- **How to fix:** Add a metadata_options block with http_tokens = "required".
- **NIST SP 800-53:** AC-3 (Access Enforcement), CM-6 (Configuration Settings)

## PG101

**Storage account allows plain HTTP** (azure, high)

- **Why it matters:** Data sent over HTTP is not encrypted, so anyone on the network path can read or change it.
- **How to fix:** Set https_traffic_only_enabled = true (called enable_https_traffic_only in older providers).
- **NIST SP 800-53:** SC-8 (Transmission Confidentiality and Integrity)

## PG102

**Storage account allows old TLS versions** (azure, medium)

- **Why it matters:** TLS 1.0 and 1.1 have known weaknesses and are no longer seen as safe.
- **How to fix:** Set min_tls_version = "TLS1_2".
- **NIST SP 800-53:** SC-8 (Transmission Confidentiality and Integrity), SC-13 (Cryptographic Protection)

## PG103

**Storage allows public access to files** (azure, high)

- **Why it matters:** Files in public containers can be read by anyone who finds the URL, with no login.
- **How to fix:** Set allow_nested_items_to_be_public = false and container_access_type = "private".
- **NIST SP 800-53:** AC-3 (Access Enforcement), SC-7 (Boundary Protection)

## PG104

**SSH or RDP is open to the whole internet** (azure, critical)

- **Why it matters:** Bots scan the internet for open SSH and RDP all day and try to guess passwords or use known bugs.
- **How to fix:** Only allow your own IP range, or close the port and use Azure Bastion.
- **NIST SP 800-53:** SC-7 (Boundary Protection), AC-17 (Remote Access)

## PG105

**Key Vault can be deleted for good right away** (azure, medium)

- **Why it matters:** Someone (or a bad script) could delete the vault and its keys forever, with no way to get them back.
- **How to fix:** Set purge_protection_enabled = true.
- **NIST SP 800-53:** CP-9 (System Backup), SC-12 (Cryptographic Key Management)

## PG106

**SQL server can be reached from the internet** (azure, high)

- **Why it matters:** Attackers can try to log in to the database server directly from anywhere.
- **How to fix:** Set public_network_access_enabled = false and use a private endpoint.
- **NIST SP 800-53:** SC-7 (Boundary Protection)

## PG107

**Linux VM allows password login** (azure, medium)

- **Why it matters:** Passwords can be guessed. SSH keys are much harder to break.
- **How to fix:** Set disable_password_authentication = true and add an admin_ssh_key.
- **NIST SP 800-53:** IA-2 (Identification and Authentication), IA-5 (Authenticator Management)
