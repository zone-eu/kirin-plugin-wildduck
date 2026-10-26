# kirin-plugin-wildduck

`kirin-plugin-wildduck` ports the existing WildDuck receiver behavior onto the Kirin hook API.

Implemented behavior includes:

- recipient resolution against WildDuck
- SRS reverse handling
- per-recipient and per-IP rate limiting
- SPF, DKIM, ARC, DMARC, and BIMI processing
- forwarding through WildDuck/ZoneMTA maildrop
- autoreplies
- message storage through WildDuck `FilterHandler`
- S/MIME and OpenPGP encryption using each recipient's WildDuck settings
- Apple push notifications for delivered messages (optional `aps` configuration)
- GridFS and S3 attachment storage using WildDuck's attachment configuration
- GELF logging compatible with the reference plugin

Rejections returned by this plugin are logged per recipient, including the SMTP response,
rejection code, and available decoded subject and From headers.

Set `aps` to match WildDuck's `imap.aps` configuration to enable Apple push notifications.
Relative certificate and key paths resolve against Kirin's working directory. Forwarding
loop detection uses `sender.loopSecret`, which must match WildDuck. S3 configuration,
including credentials or the AWS default credential chain, must also match WildDuck.

The example plugin config used by Kirin lives in:

- `config/plugins/wildduck.toml` in the Kirin project

A standalone sample of the plugin defaults lives in:

- [`config/wildduck.toml`](config/wildduck.toml)

Run `npm test` for the receiver and authentication regression tests. They use local
fixtures and mocked database/DNS services; no running MongoDB or Redis is needed.
The S/MIME round-trip test requires the `openssl` command.

## License

kirin-plugin-wildduck is licensed under the [European Union Public License 1.2](https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12) or later.

> kirin-plugin-wildduck is part of the Zone Mail Suite (ZMS), a suite of programs and modules for an efficient, fast, and modern email server.

Copyright (c) 2026 Zone Media OÜ.
