# envop
Set environment variables from 1Password Secure Notes

## Prerequisites
- Save values as custom fields of Secure Note with "envop" tag in "Private" vault
    - The field label is mapped to environment variable name
    - The field value is mapped to environment variable value
    - The field type must be "Text" or "Password"
- Install 1Password CLI
    - https://developer.1password.com/docs/cli/get-started/
- Sign in to an account once
    - Run `op signin` once. ~/.config/op/config should be created.

## Usage
```
% eval "$(envop-agent)"
% envop ${YOUR_ACCOUNT} aws printenv AWS_ACCESS_KEY_ID
AKIA................
```

### For 1Password CLI v1 users
```
% eval "$(envop-agent --use-1password-cli-v1)"
% envop ${YOUR_ACCOUNT} aws printenv AWS_ACCESS_KEY_ID
AKIA................
```

## Acknowledgments
- Functionality and command line interface are heavily inspired by [envchain](https://github.com/sorah/envchain)
- envop-agent implementation is based on [ssh-agent of OpenSSH project](https://github.com/openssh/openssh-portable)
