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
        name: 'Vineyard IP RDAP',
        version: '1.0.0',
        description:
            "Resolves each selected IP's allocation through Vineyard's cached RDAP service: adds the owning Netblock node (CIDR, netname, country) and fills the IP's organization and country. One shape across every registry, and a cache shared between analysts.",
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
            const range = rangeOf(network);
            const country = countryCode(network.country);
            const organization = holderName(doc?.entities);
            if (doc?.source) sources.add(String(doc.source));

            if (range) {
                let netblockId = netblocks.get(range);
                if (!netblockId) {
                    const created = await ctx.graph.createNode({
                        type: 'infrastructure.netblock',
                        data: {
                            cidr: range,
                            ...(network.name ? { network_name: String(network.name) } : {}),
                            ...(country ? { country_code: country } : {}),
                        },
                    });
                    netblockId = String(created.id);
                    netblocks.set(range, netblockId);
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
            if (Object.keys(patch).length) {
                await ctx.graph.updateNode(selection[i], patch);
                enriched++;
            }
        }

        if (unauthorized) {
            return {
                summary: 'Your session expired — sign in again and re-run.',
                counts: { netblocks: netblocks.size, ips_updated: enriched },
            };
        }
        const via = sources.size ? ` via ${[...sources].sort().join(', ')}` : '';
        const failures = failed ? `, ${failed} lookup(s) failed` : '';
        return {
            summary: `${netblocks.size} netblock(s), ${enriched} IP(s) enriched${via}${failures}`,
            counts: { netblocks: netblocks.size, ips_updated: enriched, failed },
        };
    },
};

export default {
    identifier: 'run.vineyard.pluginpacks.vineyard_rdap',
    content_type: 'vineyard:pluginpack',
    name: 'Vineyard IP RDAP',
    version: '1.0.0',
    description:
        "IP allocation lookup through Vineyard's cached, normalized RDAP service: one shape across every RIR, KRNIC/JPNIC whois fallback where RDAP is not served, and a cache shared between analysts instead of each one spending their own registry rate limit.",
    plugins: [vineyardRdapIp],
};
