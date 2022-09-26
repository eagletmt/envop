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
### with systemd
Setup user units first.

```
% cp envop-agent.service ~/.config/systemd/user/envop-agent.service
% systemctl --user enable --now envop-agent.service
```

Then you can connect to envop-agent managed by systemd.

```
% export ENVOP_AGENT_SOCK=$XDG_RUNTIME_DIR/envop-agent.sock
% envop ${YOUR_ACCOUNT} aws printenv AWS_ACCESS_KEY_ID
AKIA................
```

### daemonize
```
% eval "$(envop-agent)"
% envop ${YOUR_ACCOUNT} aws printenv AWS_ACCESS_KEY_ID
AKIA................
```

## For 1Password CLI v1 users
`--use-1password-cli-v1` option is required.

```
% eval "$(envop-agent --use-1password-cli-v1)"
% envop ${YOUR_ACCOUNT} aws printenv AWS_ACCESS_KEY_ID
AKIA................
```

## Acknowledgments
- Functionality and command line interface are heavily inspired by [envchain](https://github.com/sorah/envchain)
- envop-agent implementation is based on [ssh-agent of OpenSSH project](https://github.com/openssh/openssh-portable)
