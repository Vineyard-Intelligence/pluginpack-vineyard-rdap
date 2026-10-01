// Vineyard IP RDAP — IP allocation lookup through Vineyard's own RDAP service.
//
// NOT BUILT, AND THAT IS DELIBERATE. This file is the source. Every other first-party pack ships a
// minified esbuild bundle, which a registry reviewer has to either trust or unpick; a pack that
// reaches a Vineyard-operated service on the analyst's behalf is the wrong one to make anybody
// squint at. It is plain ESM, no dependencies, and short enough to read in one sitting.
//
// WHY THIS EXISTS BESIDE `IP Recon`'s RDAP plugin, which already queries rdap.org directly:
//
//   - Korean and Japanese space. KRNIC and JPNIC do not serve RDAP, so where APNIC's answer is only
//     the parent allocation the service falls back to their whois gateways and normalises the
//     result into the same shape. (Not every .kr address takes that path — APNIC answers some
//     directly, and then this is an ordinary RDAP lookup with the cache in front.)
//   - RIR rate limits. Registries throttle per source address; every analyst querying from their own
//     browser burns their own quota and gets nothing back for a range somebody already looked up.
//     The service caches by range, so the second analyst's lookup is free and instant.
//   - One shape. ARIN, RIPE, APNIC, LACNIC and AFRINIC disagree about field names; the service
//     returns network/entities/events/remarks whichever answered, and says which one did.
//
// The cost is that this pack does not work offline or against a self-hosted Vineyard without that
// service. `IP Recon`'s RDAP plugin remains the keyless, serverless option and is not deprecated.

const IP_TYPE = 'infrastructure.ip_address';

/** The address on an IP node, tolerating the legacy `value` field. */
const addressOf = (node) => String(node?.data?.ip_address ?? node?.data?.value ?? '').trim();

/** An ISO 3166-1 alpha-2 code, or undefined. The netblock type validates `^[A-Z]{2}$`, so a
 *  registry that answers "United States" must contribute nothing rather than fail the create. */
function countryCode(value) {
    const code = String(value ?? '').toUpperCase();
    return /^[A-Z]{2}$/.test(code) ? code : undefined;
}

/** The organisation that HOLDS the range, or '' — the `registrant` entity and nothing else.
 *
 *  Falling back to administrative/technical is the obvious next line and it is wrong. Measured
 *  against 1.201.0.1 (a KINX allocation): APNIC returns no registrant at all, and its administrative
 *  contact is named "IP Manager" — a role mailbox, not a company. Writing that into the IP's
 *  `organization` would look like an answer and be noise. Where APNIC omits the registrant the
 *  allocation name is still there (`network.name`, "KINXINC-KR"), and it lands on the netblock,
 *  which is where a netname belongs. */
function holderName(entities) {
    const registrant = (entities || []).find(
        (e) => Array.isArray(e?.roles) && e.roles.includes('registrant'),
    );
    return String(registrant?.name ?? '').trim();
}

/**
 * The most specific national-registry assignment covering the query, or undefined.
 *
 * Present only for KR/JP IPv4, where the service falls back to KRNIC/JPNIC whois because neither
 * serves RDAP. This is the difference the pack exists for and it is easy to leave on the floor:
 * APNIC MIRRORS those registries, so a plain RDAP answer is not wrong, it is just coarse. Measured
 * on 1.201.0.1 — APNIC returns the /16 `KINXINC-KR` and names its only contact "IP Manager", while
 * KRNIC returns the /24 actually assigned, named `KINX`. Taking the widest of the two would file a
 * host under a range 256 times too big and under no organisation at all.
 *
 * `nets` runs broad to specific, so the largest prefix length wins; a net without a parseable CIDR
 * sorts last rather than being trusted.
 */
function nirAssignment(doc) {
    const nets = doc?.nir?.nets;
    if (!Array.isArray(nets) || !nets.length) return undefined;
    const prefixLength = (net) => {
        const match = /\/(\d{1,3})$/.exec(String(net?.cidr ?? ''));
        return match ? Number(match[1]) : -1;
    };
    const best = [...nets].sort((a, b) => prefixLength(b) - prefixLength(a))[0];
    return prefixLength(best) >= 0 ? best : undefined;
}

/** 'ipv4' or 'ipv6', decided from the ADDRESS rather than from the registry.
 *
 *  `network.ip_version` is there too, but it is a field a registry may omit and this is a fact the
 *  address states on its own — a colon is only ever an IPv6 separator. Deriving it locally means the
 *  field is filled on every lookup, including one that answers with nothing else useful. */
const ipVersionOf = (address) => (address.includes(':') ? 'ipv6' : 'ipv4');

/** The originating ASN as 'AS<n>', or undefined.
 *
 *  ARIN-only, and usually absent even there — `arin_originas0_originautnums` came back empty for
 *  8.8.8.8. It costs three lines and is exactly right when a registry does supply it, so it is read
 *  opportunistically rather than advertised. ASN discovery proper is the iptoasn/Cymru pack's job. */
function originAsn(doc) {
    const nums = doc?.raw?.arin_originas0_originautnums;
    const first = Array.isArray(nums) ? nums.find((n) => Number.isFinite(Number(n))) : undefined;
    return first === undefined ? undefined : `AS${Number(first)}`;
}

// NOTE ON `registrar`: left empty on purpose. It means "sponsoring registrar", which is a domain
// concept — IP space is allocated by a REGISTRY (an RIR, or an NIR beneath it), and there is no
// registrar in the chain. Putting `whois.apnic.net` there would fill a field with a server name and
// look like an answer. Which registry actually replied is in the `raw` copy (`source`) and in the
// run summary.

/** The date a registry says the allocation was made, ISO-ish, or undefined. */
function registeredAt(doc, nir) {
    if (nir?.created) return String(nir.created);
    const events = doc?.events;
    const event = Array.isArray(events)
        ? events.find((e) => String(e?.action ?? '').toLowerCase() === 'registration')
        : undefined;
    return event?.date ? String(event.date) : undefined;
}

/** The best contact address for the allocation, or undefined.
 *
 *  Entity roles in priority order, and `abuse` LAST on purpose: a national registry answers with its
 *  own incident-response team (KRNIC's IRT is `hostmaster@nic.or.kr` for every Korean block), so
 *  taking abuse first would record the registry's address as though it were the holder's. The
 *  technical contact is the one that belongs to the organisation — `noc@kinx.net` for KINX. */
function contactEmail(entities) {
    for (const role of ['registrant', 'technical', 'administrative', 'abuse']) {
        const entity = (entities || []).find((e) => Array.isArray(e?.roles) && e.roles.includes(role));
        const email = entity?.emails?.find((x) => typeof x === 'string' && x.includes('@'));
        if (email) return String(email).trim();
    }
    return undefined;
}

// ---- contacts ---------------------------------------------------------------
// An RDAP answer carries the holder's real email addresses and phone numbers, and until now they
// survived only inside the `raw` blob — readable, but not pivotable, and picking them out by hand is
// the tedious step this pack exists to remove. They become nodes now. What follows is the set of
// rules that stops that from wrecking the graph.

/** Contacts per organisation, per kind. Registry data is third-party; a malformed or hostile answer
 *  should cost a bounded number of nodes. Measured maximum across five RIRs is two. */
const MAX_CONTACTS = 8;

/**
 * An entity that speaks for the REGISTRY rather than for the holder.
 *
 * `abuse` alone is the tell, and the reason is measurable: a national registry answers with its own
 * incident-response team for every block it serves — KRNIC returns `hostmaster@nic.or.kr` on every
 * Korean lookup, RIPE `abuse@ripe.net` on every European one. Node identity here is type + label, so
 * those are not fifty nodes, they are ONE node that collects an edge from every organisation the
 * project ever touches. After a morning's work the most connected node in the graph is a registry
 * mailbox that connects nothing to anything.
 *
 * An entity that ALSO holds a registrant/technical/administrative role is kept: for a block the
 * registry itself holds (193.0.6.0/24 is RIPE NCC's own) that address really is the holder's.
 */
const isRegistryContact = (entity) => {
    const roles = Array.isArray(entity?.roles) ? entity.roles : [];
    return roles.length > 0 && roles.every((r) => String(r).toLowerCase() === 'abuse');
};

// The typepack's own validators, copied because a create that fails them is a lost node with no
// error the analyst ever sees. Third-party text checked before it becomes graph data.
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const PHONE_RE = /^\+?[0-9 ().-]{5,}$/;

/** A dialable number, or undefined. Extensions are dropped: LACNIC answers `+598  26042222#4401`
 *  and `#` is not in the type's validator, so the whole number would be refused for the sake of a
 *  suffix. The full string stays in the record's `raw`. */
function phoneNumber(value) {
    const trimmed = String(value ?? '').split(/[#;]|\bx\b|\bext\b/i)[0].trim();
    return PHONE_RE.test(trimmed) ? trimmed : undefined;
}

/** The dialing code, only when the number states it unambiguously.
 *
 *  `+82-2-580-4601` → `82`. Country codes are one to three digits and nothing in the string says
 *  which, so this reads only up to the first separator and gives up on `+31205354444` rather than
 *  guessing `3`, `31` or `312`. All four registries measured put a separator there. */
function dialingCode(number) {
    const match = /^\+(\d{1,3})[\s.\-()]/.exec(String(number ?? ''));
    return match ? match[1] : undefined;
}

/**
 * The holder's contact addresses and numbers, de-duplicated, in one pass over both sources.
 *
 * The national-registry block is read as well as the RIR's entity list, and it is the better of the
 * two where it exists — KRNIC gives `noc@kinx.net` and `+82-2-580-460x` for the /24 actually
 * assigned, while APNIC's mirror offers a contact named "IP Manager". Same organisation, and the
 * de-duplication below means naming it twice costs nothing.
 */
function contactsOf(doc, nir) {
    const emails = new Map(); // lowercased address -> node data
    const phones = new Map(); // dialable number -> node data

    const addEmail = (value, name) => {
        const email = String(value ?? '').trim();
        if (!EMAIL_RE.test(email) || emails.size >= MAX_CONTACTS) return;
        const key = email.toLowerCase();
        if (emails.has(key)) return;
        emails.set(key, {
            email,
            ...(name ? { display_name: String(name).trim() } : {}),
            domain: email.slice(email.indexOf('@') + 1).toLowerCase(),
        });
    };
    const addPhone = (value) => {
        const number = phoneNumber(value);
        if (!number || phones.size >= MAX_CONTACTS || phones.has(number)) return;
        const code = dialingCode(number);
        phones.set(number, { number, ...(code ? { country_code: code } : {}) });
    };

    for (const entity of doc?.entities ?? []) {
        if (isRegistryContact(entity)) continue;
        // The contact's own name rides along as the address's display_name. It is often a role
        // ("IP Manager") rather than a person, which is exactly why it does not become a node of
        // its own — telling a role mailbox from a human reliably is not something this can do.
        for (const email of entity?.emails ?? []) addEmail(email, entity?.name);
        for (const phone of entity?.phones ?? []) addPhone(phone);
    }
    for (const contact of Object.values(nir?.contacts ?? {})) {
        addEmail(contact?.email, contact?.name);
        addPhone(contact?.phone);
    }
    return { emails: [...emails.values()], phones: [...phones.values()] };
}

/** Everything the service returned, minus the registry's own verbatim payload, capped.
 *
 *  `raw` on a whois_record is where the parts with no field of their own survive: allocation type,
 *  status, the full contact list, every event, the national-registry block. Dropping `doc.raw` keeps
 *  it to roughly a screenful instead of tens of kilobytes — that copy is the registry's, and the
 *  normalized view above it is the one a reader can use. */
function recordPayload(doc) {
    const { raw, ...normalized } = doc ?? {};
    const text = JSON.stringify(normalized, null, 1);
    return text.length > 8000 ? `${text.slice(0, 8000)}\n… truncated` : text;
}

/** CIDR if the registry gave one, else the range as start–end, else ''. */
function rangeOf(network) {
    if (network?.cidr) return String(network.cidr);
    if (network?.start_address && network?.end_address) {
        return `${network.start_address} - ${network.end_address}`;
    }
    return '';
}

const vineyardRdapIp = {
    manifest: {
        identifier: 'run.vineyard.plugins.vineyard_rdap_ip',
        content_type: 'vineyard:plugin',
        name: 'Vineyard RDAP IP',
        version: '1.4.2',
        description:
            "Looks up each selected IP Address through Vineyard's RDAP service and creates its Netblock (\"within netblock\"), a WHOIS Record (\"has whois\"), and the holding Organization (\"controls\" the netblock) with its email addresses and phone numbers (\"owns\", up to 8 each). Fills the IP's organization, country_code, asn and version only where empty. Korean and Japanese IPv4 ranges use the KRNIC/JPNIC assignment when available.",
        icon: 'boxes',
        author: { name: 'VINEYARD', url: 'https://vineyard.run' },
        license: 'Apache-2.0',
        platforms: { primary: 'web', web: { runtime: 'sandbox-js', entry: 'inline' } },
        io: {
            consumes: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'ip_address' },
            ],
            produces: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'netblock' },
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'whois_record' },
                { typepack: 'run.vineyard.typepacks.identity', category: 'identity', name: 'organization' },
                { typepack: 'run.vineyard.typepacks.identity', category: 'identity', name: 'email_address' },
                { typepack: 'run.vineyard.typepacks.identity', category: 'identity', name: 'phone_number' },
            ],
        },
        scopes: {
            graph: ['node:read', 'node:create', 'node:update', 'edge:create'],
            // No `network`. The destination is not this pack's to choose — `ctx.service` names a
            // Vineyard service and the host holds its address, which is what lets the call carry
            // the analyst's identity without the pack ever seeing a credential.
            services: ['rdap'],
        },
        lifecycle: { persistence: 'opt-in', controls: ['progress', 'cancel'], progress: 'determinate' },
    },

    async run(ctx) {
        // Absent on a Vineyard older than ctx.service, and on any build whose host bridge does not
        // offer it. Say which, rather than failing as though the lookup went wrong.
        // A build with no ctx.service cannot reach the service at all. Thrown, not returned: the host
        // renders a returned summary as a green "succeeded", so a broken install would read as a
        // lookup that simply found nothing. Same reasoning as the failure ending below.
        if (!ctx.service) {
            throw new Error(
                'This Vineyard build does not offer Vineyard services (ctx.service). Update the app, or use IP Recon → RDAP IP, which queries rdap.org directly.',
            );
        }
        const selection = ctx.input.selection;
        if (!selection.length) {
            return { summary: 'Select one or more IP Address nodes first', counts: { netblocks: 0 } };
        }

        const netblocks = new Map(); // range -> node id, so one /24 is created once per run
        const sources = new Set(); // which registry actually answered
        const orgs = new Set(); // distinct holders seen, for the summary
        let enriched = 0;
        let records = 0;
        let contacts = 0;
        let failed = 0;
        let unauthorized = false;

        for (let i = 0; i < selection.length && !ctx.signal?.aborted; i++) {
            const node = await ctx.graph.get(selection[i]);
            if (!node || node.type !== IP_TYPE) continue;
            const address = addressOf(node);
            if (!address) continue;

            ctx.progress?.set?.({
                percent: Math.round(((i + 1) / selection.length) * 100),
                message: `RDAP ${address}`,
            });

            let doc;
            try {
                const res = await ctx.service('rdap', encodeURIComponent(address));
                if (res.status === 401) {
                    // The host attaches the analyst's token; a 401 means the session ended, not that
                    // the service is broken. Stop rather than spend the rest of the selection on it.
                    unauthorized = true;
                    break;
                }
                if (!res.ok) {
                    failed++;
                    continue;
                }
                doc = await res.json();
            } catch {
                failed++;
                continue;
            }

            const network = doc?.network ?? {};
            const nir = nirAssignment(doc);
            const range = nir?.cidr ? String(nir.cidr) : rangeOf(network);
            const netname = String(nir?.name ?? network.name ?? '').trim();
            const country = countryCode(nir?.country ?? network.country);
            // A national registry names the ASSIGNEE where the RIR mirror names a role contact, so
            // it is the answer for `organization` when there is no registrant — but only then: an
            // explicit registrant is the registry's own statement of who holds the block.
            const organization = holderName(doc?.entities) || String(nir?.name ?? '').trim();
            if (doc?.source) sources.add(String(doc.source));
            if (nir) sources.add(country === 'JP' ? 'JPNIC' : 'KRNIC');

            const asn = originAsn(doc);

            if (range) {
                let netblockId = netblocks.get(range);
                if (!netblockId) {
                    const created = await ctx.graph.createNode({
                        type: 'infrastructure.netblock',
                        data: {
                            cidr: range,
                            ...(netname ? { network_name: netname } : {}),
                            ...(country ? { country_code: country } : {}),
                            ...(asn ? { asn } : {}),
                        },
                    });
                    netblockId = String(created.id);
                    netblocks.set(range, netblockId);
                }
                await ctx.graph.createEdge({ from: selection[i], to: netblockId, label: 'within netblock' });
            }

            // The registration record, keyed by the ADDRESS and hung off it.
            //
            // Not by CIDR, and not off the netblock, though both read as tidier: `whois_record`
            // declares `subject` to be "the domain or IP this record describes (its identity)", and
            // `has_whois` declares its endpoints as domain or ip_address. A netblock is neither. The
            // type is shared with domain WHOIS on purpose — same protocol family, same fields — so a
            // plugin inventing its own reading of it is exactly the drift the typepack exists to
            // prevent, and it would put an edge on the canvas that the edge type does not allow.
            //
            // The cost is honest duplication: fifty addresses in one /24 produce fifty records
            // saying the same thing. That is the type's design — one record per subject — and the
            // netblock above is where the per-range view already lives.
            const registeredOn = registeredAt(doc, nir);
            const email = contactEmail(doc?.entities);
            const record = await ctx.graph.createNode({
                type: 'infrastructure.whois_record',
                data: {
                    subject: address,
                    ...(organization ? { registrant: organization } : {}),
                    ...(email ? { registrant_email: email } : {}),
                    ...(registeredOn ? { created_at: registeredOn } : {}),
                    raw: recordPayload(doc),
                },
            });
            await ctx.graph.createEdge({ from: selection[i], to: String(record.id), label: 'has whois' });
            records++;

            // The holder, and the way to reach it.
            //
            // WHY AN ORGANISATION NODE AND NOT AN EDGE FROM THE NETBLOCK: `identity.owns` runs
            // from a person, organisation or handle to an email/phone, and there is no edge type in
            // either pack that takes a netblock to a contact. So the organisation is not decoration
            // here, it is the only legal anchor — and it earns its place anyway, because two
            // netblocks held by one company become connected the moment the second is looked up.
            //
            // No organisation means no contacts. An address with nothing to attach it to is a
            // floating node, and "who does this belong to" is the question the analyst is asking.
            if (organization) {
                const org = await ctx.graph.createNode({
                    type: 'identity.organization',
                    data: { name: organization, ...(country ? { country } : {}) },
                });
                const orgId = String(org.id);
                if (netblocks.has(range)) {
                    await ctx.graph.createEdge({ from: orgId, to: netblocks.get(range), label: 'controls' });
                }
                const { emails, phones } = contactsOf(doc, nir);
                for (const data of emails) {
                    const n = await ctx.graph.createNode({ type: 'identity.email_address', data });
                    await ctx.graph.createEdge({ from: orgId, to: String(n.id), label: 'owns' });
                    contacts++;
                }
                for (const data of phones) {
                    const n = await ctx.graph.createNode({ type: 'identity.phone_number', data });
                    await ctx.graph.createEdge({ from: orgId, to: String(n.id), label: 'owns' });
                    contacts++;
                }
                orgs.add(organization.toLowerCase());
            }

            // A DELTA, not a snapshot. Passing `{...node.data, ...}` would write back every field as
            // this run happened to read it, clobbering anything another run filled in between — the
            // whole point of update being fill-merge. Only the fields this lookup actually produced,
            // and only where the node has nothing already: RDAP is authoritative about allocation,
            // not about what an analyst has since corrected by hand.
            const patch = {};
            if (organization && !node.data.organization) patch.organization = organization;
            if (country && !node.data.country_code) patch.country_code = country;
            if (asn && !node.data.asn) patch.asn = asn;
            // Not from the registry — see ipVersionOf. Filled even when the lookup found nothing
            // else, because the address always says it.
            if (!node.data.version) patch.version = ipVersionOf(address);
            if (Object.keys(patch).length) {
                await ctx.graph.updateNode(selection[i], patch);
                enriched++;
            }
        }

        if (unauthorized) {
            throw new Error('Your session expired — sign in again and re-run.');
        }
        // Every lookup failed and nothing came back. A RETURNED summary is always a green
        // "succeeded" on the run's row — and with nothing staged the toast reads "No changes" — so
        // returning here made a service that was down look like addresses nobody has registered.
        // A partial run still succeeds; the count of failures is in the summary either way.
        if (failed && !records && !netblocks.size) {
            throw new Error(
                `every RDAP lookup failed (${failed} address(es)) — the service may be unreachable`,
            );
        }
        const via = sources.size ? ` via ${[...sources].sort().join(', ')}` : '';
        const failures = failed ? `, ${failed} lookup(s) failed` : '';
        return {
            summary:
                `${netblocks.size} netblock(s), ${orgs.size} organisation(s), ${contacts} contact(s), ` +
                `${records} whois record(s), ${enriched} IP(s) enriched${via}${failures}`,
            counts: {
                netblocks: netblocks.size,
                organizations: orgs.size,
                contacts,
                whois_records: records,
                ips_updated: enriched,
                failed,
            },
        };
    },
};

export default {
    identifier: 'run.vineyard.pluginpacks.vineyard_rdap',
    content_type: 'vineyard:pluginpack',
    name: 'Vineyard RDAP IP',
    version: '1.4.3',
    description: "IP address registration lookups through Vineyard's RDAP service: the covering netblock, a WHOIS record, and the holding organization with its contacts.",
    plugins: [vineyardRdapIp],
};
