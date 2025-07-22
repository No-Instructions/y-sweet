# Relay Server

[Relay](https://relay.md) adds real-time collaboration to Obsidian. Share exactly the folders you want, keep the rest of your vault private, and work together even when offline. The server in this repository powers that experience.

Relay Server is a fork of [jamsocket/y-sweet](https://github.com/jamsocket/y-sweet). It exposes the same CRDT-based document store under a new name and integrates with Relay's Control Plane for authentication and permissions.

## Features

 - Real‑time collaboration engine built atop y-crdt, enabling high-performance conflict‑free shared editing
 - Use the Relay.md control plane for login and access control management
 - Fully private self-hosting of your documents and attachments (no connection to the public internet required!)
 - 1-step deployment into your Tailscale Tailnet
 - Persistence to S3‑compatible object storage (S3, Cloudflare R2, Minio)
 - Flexible deployment/isolation with single server or session‑per‑document model
 - Python SDK
 - Webhook Event Delivery
 - OpenAPI documentation available at `/docs` (spec at `/openapi.yaml`)


## Self-hosting

> :information_source: **Note:** The Relay Server and Relay Obsidian Plugin are open source, but the Relay Control Plane is not open source. Using a Self-Hosted Relay Server with more than 3 collaborators requires a paid license to support the development of Relay.


Self-hosting gives you complete privacy for your notes and attachments. Relay's Control Plane handles login and permissions, but cannot read your content. The recommended setup uses Docker with Cloudflare R2 for persistence.

See [relay-server-template](https://github.com/no-instructions/relay-server-template) for detailed hosting instructions and deployment templates.


## Contact

- Discord: [https://discord.system3.md](https://discord.system3.md)
- Email: contact@system3.md


## Acknowledgements

Relay Server builds on [y-sweet](https://github.com/jamsocket/y-sweet) by the folks at Jamsocket, which in turn uses [y-crdt](https://github.com/y-crdt/y-crdt).

The server source code is MIT licensed.
