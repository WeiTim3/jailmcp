# Security Policy

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** on this repository
(Security → Report a vulnerability) instead of a public issue. Include the
version (`jb_device_info`), the tool name, and a minimal reproduction.

Do not attach the bridge token, the contents of `.bridge-state`, or device
data. A redacted `jb_log_tail` excerpt with its `ref` is enough.

## Threat model in one paragraph

The bridge runs as UID 501 (`mobile`) behind launchd and listens only on
`127.0.0.1:18765` with a 64-hex bearer token. That token is readable by any
unsandboxed process running as `mobile`, so it is **not** a boundary against
jailbreak-level malware. `jb_exec` is an arbitrary `mobile` shell, and
`jb_find` can read the whole data volume; both are capabilities, not sandboxes.
There is no root helper. The service never reads, prints or uploads the token
and never inherits API keys or environment secrets into commands.

## Scope

In scope: authentication bypass, path traversal outside a configured project
root, symlink/hardlink escapes, private-state disclosure, update/rollback
integrity, privilege escalation beyond `mobile`, denial of service that
survives a restart.

Out of scope: what a user or agent does with a legitimately authenticated
`jb_exec`, data readable by a process that is already running as `mobile`, and
issues that require an already-compromised jailbreak.
