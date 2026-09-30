# Vineyard RDAP IP

IP allocation lookup through **Vineyard's own cached RDAP service**, rather than straight to the
registries.

| | |
| --- | --- |
| Pack | `run.vineyard.pluginpacks.vineyard_rdap` |
| Consumes | `infrastructure.ip_address` |
| Produces | `infrastructure.netblock` · `infrastructure.whois_record` · `identity.organization` · `identity.email_address` · `identity.phone_number` |
| Scopes | `graph` (read/create/update, edge create) · `services: ["rdap"]` |

## What it does

For every selected IP Address node it asks Vineyard's RDAP service who holds the range, then:

- creates the owning **Netblock** — `cidr`, `network_name`, `country_code`, `asn` — and links the IP
  to it as `within netblock`. One netblock per range, however many of the selected IPs fall inside it.
- creates its **WHOIS Record** on the IP (`has whois`): `registrant`, `registrant_email`,
  `created_at`, and a `raw` copy of everything else the lookup returned — allocation type, status,
  every event, the full contact list, the national-registry block.
- creates the holding **Organization**, links it to the netblock (`controls`), and hangs its
  **email addresses** and **phone numbers** off it as their own nodes (`owns`). See below.
- fills the IP's `organization`, `country_code`, `asn` and `version` **only where they are empty**.

`version` is decided from the address rather than from the registry, so it is filled even on a
lookup that returns nothing else.

The `raw` copy omits the registry's own verbatim payload (`doc.raw`) and is capped at 8,000
characters.

### Why the record hangs off the IP and not the netblock

The `has whois` edge only runs from a domain or an IP, so the record is keyed by IP: fifty addresses
in one /24 produce fifty records saying the same thing. The per-range view is the netblock.

`registrar` is left **empty**: it is a domain concept, and IP space is allocated by a registry, not
a registrar. Which registry replied is in the `raw` copy and in the run summary.

Fields this lookup did not produce are not written back, so a value an analyst corrected by hand —
or another collection filled a moment ago — survives.

## Contacts become nodes (1.4.0)

The holder's email addresses and phone numbers from the RDAP answer become their own nodes.

```
IP Address ──within netblock──▶ Netblock ◀──controls── Organization ──owns──▶ Email Address
     └──has whois──▶ WHOIS Record                            └──owns──▶ Phone Number
```

**Why an Organization node.** No edge type takes a netblock to a contact, so the organisation is the
anchor. Two netblocks held by one company become connected the moment the second is looked up.

**No holder, no contacts.** Where neither a registrant nor a national-registry assignee exists, no
contact nodes are created. The lookup still produces the netblock and the record.

### The rule that keeps this from wrecking the graph

**An entity whose ONLY role is `abuse` gets no node.** Node identity in Vineyard is type + label, so
an address like KRNIC's `hostmaster@nic.or.kr`, returned on every Korean block, would become one hub
node linked to every Korean organisation in the project. RIPE does the same with `abuse@ripe.net`.

The test is the role list, not the address: where `abuse@ripe.net` appears on a *technical* role for
RIPE NCC's own block, it is kept.

### Smaller decisions

| | |
| --- | --- |
| Contact names | ride along as the address's `display_name`. They are often a role ("IP Manager", "Managing Director") rather than a person, so they do not become `identity.person` nodes. |
| `country_code` on a phone | read only up to the first separator: `+82-2-580-4601` → `82`. `+31205354444` gets none rather than a guess between `3`, `31` and `312`. |
| Extensions | dropped (`#` fails the type's validator). The full string stays in `raw`. |
| Malformed values | refused. `noc@sixes` has an `@` and still fails `identity.email_address`'s validator. |
| Volume | capped at 8 per kind per organisation. |

## Why not just query RDAP directly

[`IP Recon`](https://github.com/Vineyard-Intelligence/pluginpack-ip-recon)'s RDAP plugin does
exactly that, keylessly, with no server involved. It is not deprecated and it is the right choice
when you want no dependency on Vineyard's infrastructure. This pack trades that independence for
three things:

- **A shared cache.** Registries throttle per source address. Querying from each analyst's browser
  spends each analyst's own quota, and gets nothing back for a range a colleague looked up an hour
  ago. The service caches by range.
- **KRNIC / JPNIC.** Neither serves RDAP, and APNIC *mirrors* them coarsely — for `1.201.0.1` APNIC
  returns the **/16** `KINXINC-KR`, while KRNIC returns the **/24** actually assigned, to **KINX**.
  This pack takes the national registry's answer where the service supplies one.
- **One shape.** ARIN, RIPE, APNIC, LACNIC and AFRINIC disagree about field names. The service
  returns `network` / `entities` / `events` / `remarks` whichever answered, and says which one did —
  the run summary names it.

## Where `organization` and the contact address come from

`organization` is the **`registrant`** entity, then the **national registry's** assignee name.
Nothing else — administrative and technical contacts are people and role mailboxes, not the
organisation holding the block.

Where neither exists the field is left empty. The allocation name is still recorded, as the
netblock's `network_name`.

`registrant_email` walks the roles registrant → technical → administrative → **abuse last**, because
a national registry's abuse contact is its own incident-response team (KRNIC returns
`hostmaster@nic.or.kr` for every Korean block), not the holder's address.

## The service, and the scope

This pack declares no `network` scope and holds no credential: it reaches only Vineyard's RDAP
service, under the analyst's own session. The install gate therefore shows **Vineyard rdap** rather
than an endpoint URL — see [the scopes reference](https://docs.vineyard.run/reference/scopes/#services).

A `401` means the analyst's session ended. The run stops and says so.

## Verifying

```bash
node verify.mjs
```

Twenty-two scenarios against recorded responses from the live service, plus a check that the JSON
manifest and the manifest embedded in the bundle still agree.

## The bundle is not minified

`dist/pack.mjs` is the source: plain ESM, no dependencies, no build step.

## License

Apache-2.0
