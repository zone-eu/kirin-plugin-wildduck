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
- GELF logging compatible with the reference plugin

The example plugin config used by Kirin lives in:

- `config/plugins/wildduck.toml` in the Kirin project

A standalone sample of the plugin defaults lives in:

- [`config/wildduck.toml`](config/wildduck.toml)

## License

kirin-plugin-wildduck is licensed under the [European Union Public License 1.2](https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12) or later.

> kirin-plugin-wildduck is part of the Zone Mail Suite (ZMS), a suite of programs and modules for an efficient, fast, and modern email server.

Copyright (c) 2026 Zone Media OÜ.
