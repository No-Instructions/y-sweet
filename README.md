# Relay Server

[Relay](https://relay.md) adds real-time collaboration to Obsidian. Share exactly the folders you want, keep the rest of your vault private, and work together even when offline. The server in this repository powers that experience.

Relay Server is a fork of [jamsocket/y-sweet](https://github.com/jamsocket/y-sweet). It exposes the same CRDT-based document store under a new name and integrates with Relay's Control Plane for authentication and permissions.

## Features

- **Share folders, not vaults** – collaborate on specific folders while keeping personal notes private.
- **Built for speed** – live cursors and low-latency updates keep collaboration snappy.
- **Works offline** – edits sync automatically when clients reconnect.
- **Local-first storage** – your content stays on your server and in your control.

## Self-hosting

Self-hosting gives you complete privacy for your notes and attachments. Relay's Control Plane handles login and permissions, but cannot read your content. The recommended setup uses Docker with Cloudflare R2 for persistence.

See [relay-server-template](https://github.com/no-instructions/relay-server-template) for detailed hosting instructions and deployment templates.

## Contact

- Discord: [https://discord.system3.md](https://discord.system3.md)
- Email: contact@system3.md

## Acknowledgements

Relay Server builds on [y-sweet](https://github.com/jamsocket/y-sweet) by the folks at Jamsocket, which in turn uses [y-crdt](https://github.com/y-crdt/y-crdt).

The server source code is MIT licensed.
