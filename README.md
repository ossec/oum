# OSSEC Updater Modified (OUM)

# Description

OUM is an interactive rule and CDB updater for OSSEC. Loosely based on the yum package manager, it can be used to update OSSEC rules/decoders, malware signatures, compliance checks,  and threat intelligence CDB files.

# Usage

```
OSSEC Updater Modified (OUM) 1.0.0

Usage: oum [options] COMMAND

 List of Commands:

  help			Display a helpful usage message
  list			List pending updates
  update		Update system
  configure		Configure system
  version		Display version
```

# Installing OSSEC Updater Modified (OUM)
Run the OUM installer
`wget -q -O - https://updates.atomicorp.com/installers/oum | bash`

# Configuring OSSEC Updater Modified (OUM)
After installation is complete, users can configure OUM by running
`oum configure`

# Updating rules with OSSEC Updater Modified (OUM) 
Rulsets can be be updated with `oum update` after OUM has been installed and configured.

# Screenshots

![test](https://github.com/ossec/oum/blob/main/images/oum-v1.gif)
