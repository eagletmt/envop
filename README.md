# envop
Set environment variables from 1Password Secure Notes

## Prerequisites
- Save values as custom fields of Secure Note with "envop" tag in "Private" vault
    - The field label is mapped to environment variable name
    - The field value is mapped to environment variable value
    - The field type must be "Text" or "Password"
- Install 1Password CLI
    - https://support.1password.com/command-line-getting-started/
- Sign in to an account once
    - Run `op signin` once. ~/.config/op/config should be created.

## Usage
```
% eval "$(envop-agent)"
% envop ${YOUR_ACCOUNT} aws printenv AWS_ACCESS_KEY_ID
AKIA................
```
