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
  every event, the full contact list, the national-registry block. That last field is there because
  an RDAP answer carries far more than the typed fields have room for, and the parts without a home
  are often the ones worth reading.
- creates the holding **Organization**, links it to the netblock (`controls`), and hangs its
  **email addresses** and **phone numbers** off it as their own nodes (`owns`). See below.
- fills the IP's `organization`, `country_code`, `asn` and `version` **only where they are empty**.

`version` is decided from the address rather than from the registry — a colon is only ever an IPv6
separator — so it is filled even on a lookup that returns nothing else.

The `raw` copy deliberately omits the registry's own verbatim payload (`doc.raw`), which is tens of
kilobytes of the same facts in a shape nobody reads. It is capped at 8,000 characters.

### Why the record hangs off the IP and not the netblock

`infrastructure.whois_record` is shared with domain WHOIS, and its declaration decides this:
`subject` is *"the domain or IP this WHOIS record describes (its identity)"*, and the `has_whois`
edge runs `from: [domain, ip_address]`. A CIDR is neither of those and a netblock is not a permitted
endpoint — so keying by range, which reads tidier, would put an edge on the canvas that the edge
type does not allow.

The cost is honest duplication: fifty addresses in one /24 produce fifty records saying the same
thing. That is what "one record per subject" means, and the per-range view already exists — it is
the netblock.

`registrar` is left **empty**. It means "sponsoring registrar", which is a domain concept: IP space
is allocated by a *registry* (an RIR, or an NIR beneath it) and there is no registrar in the chain.
`whois.apnic.net` is a server name, and putting it there would fill a field with a wrong answer that
reads like a right one. Which registry replied is in the `raw` copy and in the run summary.

The update is a delta, not a snapshot. Fields this lookup did not produce are not written back, so a
value an analyst corrected by hand — or another collection filled a moment ago — survives.

## Contacts become nodes (1.4.0)

An RDAP answer carries the holder's real email addresses and phone numbers. Until 1.4.0 they
survived only inside `raw` — readable, but not pivotable, and picking them out by hand was the
tedious step this pack exists to remove.

```
IP Address ──within netblock──▶ Netblock ◀──controls── Organization ──owns──▶ Email Address
     └──has whois──▶ WHOIS Record                            └──owns──▶ Phone Number
```

**Why an Organization node.** `identity.owns` runs from a person, organisation or handle to an
email or phone, and no edge type in either pack takes a netblock to a contact — so the organisation
is the only legal anchor. It earns the place anyway: two netblocks held by one company become
connected the moment the second is looked up.

**No holder, no contacts.** Where neither a registrant nor a national-registry assignee exists there
is nothing to attach an address to, and a floating email node does not answer "who does this belong
to". The lookup still produces the netblock and the record.

### The rule that keeps this from wrecking the graph

**An entity whose ONLY role is `abuse` gets no node.** Node identity in Vineyard is type + label, so
`hostmaster@nic.or.kr` is not one node per Korean lookup — it is **one node that collects an edge
from every Korean organisation in the project**. It is KRNIC's incident-response desk, returned on
every Korean block, and it connects nothing to anything. RIPE does the same with `abuse@ripe.net`.

The test is the role list, not the address. RIPE NCC holds `193.0.6.0/24` itself, and there
`abuse@ripe.net` on a *technical* role genuinely is the holder's — a rule keyed on the address would
have thrown it away.

### Smaller decisions, each one measured

| | |
| --- | --- |
| Contact names | ride along as the address's `display_name`. They are often a role ("IP Manager", "Managing Director") rather than a person, which is why they do not become `identity.person` nodes — telling one from the other reliably is not something this can do. |
| `country_code` on a phone | read only up to the first separator: `+82-2-580-4601` → `82`. Codes are one to three digits and nothing in the string says which, so `+31205354444` gets none rather than a guess between `3`, `31` and `312`. |
| Extensions | dropped. LACNIC answers `+598  26042222#4401`, and `#` is not in the type's validator — creating it verbatim would be a node that silently never appears. The full string stays in `raw`. |
| Malformed values | refused. `noc@sixes` has an `@` and still fails `identity.email_address`'s validator. Registry text is third-party and these are validated fields. |
| Volume | capped at 8 per kind per organisation. The measured maximum across five RIRs is two; the cap is there because a broken parser upstream should cost a bounded review, not six hundred staged nodes. |

## Why not just query RDAP directly

[`IP Recon`](https://github.com/Vineyard-Intelligence/pluginpack-ip-recon)'s RDAP plugin does
exactly that, keylessly, with no server involved. It is not deprecated and it is the right choice
when you want no dependency on Vineyard's infrastructure. This pack trades that independence for
three things:

- **A shared cache.** Registries throttle per source address. Querying from each analyst's browser
  spends each analyst's own quota, and gets nothing back for a range a colleague looked up an hour
  ago. The service caches by range.
- **KRNIC / JPNIC.** Neither serves RDAP, and APNIC *mirrors* them — so a plain RDAP answer for a
  Korean address is not wrong, it is coarse. Measured on `1.201.0.1`: APNIC returns the **/16**
  `KINXINC-KR` and its only contact is named "IP Manager", while KRNIC returns the **/24** actually
  assigned, to **KINX**. This pack takes the national registry's answer where the service supplies
  one, so the host is filed under the range it was really assigned and under a real organisation.
- **One shape.** ARIN, RIPE, APNIC, LACNIC and AFRINIC disagree about field names. The service
  returns `network` / `entities` / `events` / `remarks` whichever answered, and says which one did —
  the run summary names it.

## Where `organization` and the contact address come from

`organization` is the **`registrant`** entity, then the **national registry's** assignee name.
Nothing else.

Administrative and technical contacts are people and role mailboxes, not the organisation holding
the block — APNIC's only contact for `1.201.0.1` is named **"IP Manager"**, and writing that into an
IP's `organization` would look like an answer. A registrant, where a registry gives one, is that
registry's own statement of who holds the block and outranks everything.

Where neither exists the field is left empty. The allocation name is still recorded, as the
netblock's `network_name`, which is what a netname is.

`registrant_email` walks the roles registrant → technical → administrative → **abuse last**. Abuse
is last rather than first because a national registry answers with its own incident-response team —
KRNIC returns `hostmaster@nic.or.kr` for every Korean block — and recording that as the holder's
address would be wrong on every KR lookup. The technical contact is the organisation's own:
`noc@kinx.net` for KINX.

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

Twenty-two scenarios against responses the live service actually returned, plus a check that the JSON
manifest and the manifest embedded in the bundle still agree — they are two copies of one
declaration, the registry validates the first and the worker runs the second, so a scope added to
one and not the other is a pack that passes review and then cannot work.

## The bundle is not minified

`dist/pack.mjs` is the source: plain ESM, no dependencies, no build step. A pack that reaches a
Vineyard-operated service on the analyst's behalf is the wrong one to make a reviewer unpick.

## License

Apache-2.0
