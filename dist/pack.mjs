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
        version: '1.2.0',
        description: "IP allocation lookup through Vineyard's cached RDAP service.",
        icon: 'boxes',
        author: { name: 'VINEYARD.RUN', url: 'https://vineyard.run' },
        license: 'Apache-2.0',
        platforms: { primary: 'web', web: { runtime: 'sandbox-js', entry: 'inline' } },
        io: {
            consumes: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'ip_address' },
            ],
            produces: [
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'netblock' },
                { typepack: 'run.vineyard.typepacks.infrastructure', category: 'infrastructure', name: 'whois_record' },
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
        if (!ctx.service) {
            return {
                summary: 'This Vineyard build does not offer Vineyard services (ctx.service). Update the app, or use IP Recon → RDAP IP, which queries rdap.org directly.',
                counts: { netblocks: 0 },
            };
        }
        const selection = ctx.input.selection;
        if (!selection.length) {
            return { summary: 'Select one or more IP Address nodes first', counts: { netblocks: 0 } };
        }

        const netblocks = new Map(); // range -> node id, so one /24 is created once per run
        const sources = new Set(); // which registry actually answered
        let enriched = 0;
        let records = 0;
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

                    // The registration record for the ALLOCATION, so it is created once per range
                    // rather than once per address — an RDAP answer describes the block, not the
                    // host. It is where the parts with no field of their own live: allocation type,
                    // status, dates, the contact list, and the national-registry block.
                    const registeredOn = registeredAt(doc, nir);
                    const email = contactEmail(doc?.entities);
                    const record = await ctx.graph.createNode({
                        type: 'infrastructure.whois_record',
                        data: {
                            subject: range,
                            ...(organization ? { registrant: organization } : {}),
                            ...(email ? { registrant_email: email } : {}),
                            ...(doc?.source ? { registrar: String(doc.source) } : {}),
                            ...(registeredOn ? { created_at: registeredOn } : {}),
                            raw: recordPayload(doc),
                        },
                    });
                    await ctx.graph.createEdge({ from: netblockId, to: String(record.id), label: 'has whois' });
                    records++;
                }
                await ctx.graph.createEdge({ from: selection[i], to: netblockId, label: 'within netblock' });
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
            return {
                summary: 'Your session expired — sign in again and re-run.',
                counts: { netblocks: netblocks.size, whois_records: records, ips_updated: enriched },
            };
        }
        const via = sources.size ? ` via ${[...sources].sort().join(', ')}` : '';
        const failures = failed ? `, ${failed} lookup(s) failed` : '';
        return {
            summary: `${netblocks.size} netblock(s), ${records} whois record(s), ${enriched} IP(s) enriched${via}${failures}`,
            counts: { netblocks: netblocks.size, whois_records: records, ips_updated: enriched, failed },
        };
    },
};

export default {
    identifier: 'run.vineyard.pluginpacks.vineyard_rdap',
    content_type: 'vineyard:pluginpack',
    name: 'Vineyard RDAP IP',
    version: '1.2.0',
    description: "IP allocation lookup through Vineyard's cached RDAP service.",
    plugins: [vineyardRdapIp],
};
