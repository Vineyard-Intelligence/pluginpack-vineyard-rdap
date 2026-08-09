# Vineyard IP RDAP

IP allocation lookup through **Vineyard's own cached RDAP service**, rather than straight to the
registries.

| | |
| --- | --- |
| Pack | `run.vineyard.pluginpacks.vineyard_rdap` |
| Consumes | `infrastructure.ip_address` |
| Produces | `infrastructure.netblock` |
| Scopes | `graph` (read/create/update, edge create) · `services: ["rdap"]` |

## What it does

For every selected IP Address node it asks Vineyard's RDAP service who holds the range, then:

- creates the owning **Netblock** (CIDR, netname, country) and links the IP to it as
  `within netblock` — one netblock per range, however many of the selected IPs fall inside it;
- fills the IP's `organization` and `country_code` **only where they are empty**.

The update is a delta, not a snapshot. Fields this lookup did not produce are not written back, so a
value an analyst corrected by hand — or another collection filled a moment ago — survives.

## Why not just query RDAP directly

[`IP Recon`](https://github.com/Vineyard-Intelligence/pluginpack-ip-recon)'s RDAP plugin does
exactly that, keylessly, with no server involved. It is not deprecated and it is the right choice
when you want no dependency on Vineyard's infrastructure. This pack trades that independence for
three things:

- **A shared cache.** Registries throttle per source address. Querying from each analyst's browser
  spends each analyst's own quota, and gets nothing back for a range a colleague looked up an hour
  ago. The service caches by range.
- **KRNIC / JPNIC.** Neither serves RDAP. Where APNIC answers only with the parent allocation, the
  service falls back to their whois gateways and normalises the result into the same shape. (Not
  every `.kr` address takes that path — APNIC answers many directly.)
- **One shape.** ARIN, RIPE, APNIC, LACNIC and AFRINIC disagree about field names. The service
  returns `network` / `entities` / `events` / `remarks` whichever answered, and says which one did —
  the run summary names it.

## `organization` comes from the registrant, and from nothing else

Administrative and technical contacts are people and role mailboxes, not the organisation holding
the block. Measured against `1.201.0.1`, a KINX allocation: APNIC returns no `registrant` at all,
and its administrative contact is named **"IP Manager"**. Writing that into an IP's `organization`
would look like an answer.

Where the registrant is missing, the allocation name is still recorded — as the netblock's
`network_name` (`KINXINC-KR`), which is what a netname is.

## The service, and the scope

This pack declares no `network` scope. It cannot reach an arbitrary host, and it never sees a
credential: `ctx.service('rdap', …)` names a *service*, the host holds that service's address and
attaches the analyst's identity to the call. That is why the install gate shows **Vineyard rdap**
rather than an endpoint URL — see
[the scopes reference](https://docs.vineyard.run/reference/scopes/#services).

A `401` means the analyst's session ended. The run stops and says so, rather than spending the rest
of the selection on a dead session.

## Verifying

```bash
node verify.mjs
```

Eight scenarios against responses the live service actually returned, plus a check that the JSON
manifest and the manifest embedded in the bundle still agree — they are two copies of one
declaration, the registry validates the first and the worker runs the second, so a scope added to
one and not the other is a pack that passes review and then cannot work.

## The bundle is not minified

`dist/pack.mjs` is the source: plain ESM, no dependencies, no build step. A pack that reaches a
Vineyard-operated service on the analyst's behalf is the wrong one to make a reviewer unpick.

## License

Apache-2.0
