// Drives the plugin against RESPONSES THE REAL SERVICE GAVE, with a stub ctx.
//
// The fixtures below are trimmed copies of what auxiliary.vineyard.run/rdap actually returned for
// 8.8.8.8 and 1.201.0.1 — an ARIN answer and an APNIC one. The APNIC case is the whole reason this
// file exists: it has no `registrant` entity, and its administrative contact is called "IP Manager".
// The obvious registrant→administrative→technical fallback would write that into the IP's
// `organization`, which looks like an answer and is a role mailbox. Nothing but running it noticed.
//
// Also checks that the JSON manifest and the manifest embedded in the bundle still agree. They are
// two copies of the same declaration — the registry validates one and the worker runs the other —
// so a scope added to one and not the other is a pack that passes review and then cannot work.
//
// Run with: node verify.mjs

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import pack from './dist/pack.mjs';

const ARIN = {
    query: '8.8.8.8',
    network: { handle: 'NET-8-8-8-0-2', name: 'GOGL', cidr: '8.8.8.0/24', ip_version: 'v4', type: 'DIRECT ALLOCATION' },
    entities: [
        { handle: 'ABUSE5250-ARIN', roles: ['abuse'], name: 'Abuse', emails: ['network-abuse@google.com'] },
        { handle: 'GOGL', roles: ['registrant'], name: 'Google LLC', emails: [] },
        { handle: 'ZG39-ARIN', roles: ['administrative', 'technical'], name: 'Google LLC', emails: ['arin-contact@google.com'] },
    ],
    events: [{ action: 'last changed', date: '2023-12-28T17:24:56-05:00' }, { action: 'registration', date: '2023-12-28T17:24:33-05:00' }],
    source: 'whois.arin.net',
    // The registry's verbatim payload. Present in every real answer and tens of kilobytes of it —
    // the record's `raw` must hold the normalized view, not this.
    raw: { objectClassName: 'ip network', arin_originas0_originautnums: [], vcardArray: ['vcard', []] },
};
// APNIC mirrors KRNIC, so this answer is coarse rather than wrong: the /16 and a contact called
// "IP Manager". The `nir` block beside it is what KRNIC's own whois said — the /24 actually
// assigned, to KINX. Copied from a live response for 1.201.0.1.
const APNIC = {
    query: '1.201.0.1',
    network: { handle: '1.201.0.0 - 1.201.255.255', name: 'KINXINC-KR', cidr: '1.201.0.0/16', country: 'KR' },
    entities: [
        { handle: 'MI443-KR', roles: ['technical', 'administrative'], name: 'IP Manager', emails: ['noc@kinx.net'] },
        // KRNIC's incident-response team, returned for EVERY Korean block. Taking `abuse` first
        // would file the registry's own address as though it belonged to the holder.
        { handle: 'IRT-KRNIC-KR', roles: ['abuse'], name: 'IRT-KRNIC-KR', emails: ['hostmaster@nic.or.kr'] },
    ],
    source: 'whois.apnic.net',
    nir: {
        query: '1.201.0.1',
        nets: [
            { range: '1.201.0.0 - 1.201.255.255', cidr: '1.201.0.0/16', name: 'KINX', handle: 'KINXINC', country: 'KR' },
            { range: '1.201.0.0 - 1.201.0.255', cidr: '1.201.0.0/24', name: 'KINX', handle: 'KINXINC', country: 'KR' },
        ],
    },
};
/** The same allocation as the RIR alone would report it — no national-registry answer. */
const APNIC_NO_NIR = { ...APNIC, nir: undefined };

/** A ctx that records what the plugin did instead of touching a graph. */
function stubCtx(nodes, responses) {
    const created = [];
    const edges = [];
    const updates = [];
    return {
        ctx: {
            input: { selection: Object.keys(nodes) },
            graph: {
                get: async (id) => nodes[id] ?? null,
                createNode: async (draft) => {
                    created.push(draft);
                    return { id: `new-${created.length}` };
                },
                createEdge: async (edge) => edges.push(edge),
                updateNode: async (id, patch) => updates.push({ id, patch }),
            },
            service: async (name, path) => {
                assert.equal(name, 'rdap', 'the plugin must not name any other service');
                const body = responses[decodeURIComponent(path)];
                if (body === 401) return { ok: false, status: 401, json: async () => ({}) };
                assert.ok(body, `no fixture for ${path}`);
                return { ok: true, status: 200, json: async () => body };
            },
        },
        created,
        edges,
        updates,
    };
}

const plugin = pack.plugins[0];
const ipNode = (id, ip, data = {}) => [id, { id, type: 'infrastructure.ip_address', data: { ip_address: ip, ...data } }];

// --- 1. ARIN: netblock, whois record, and the IP filled in ------------------------------------
{
    const { ctx, created, edges, updates } = stubCtx(
        Object.fromEntries([ipNode('n1', '8.8.8.8')]),
        { '8.8.8.8': ARIN },
    );
    const out = await plugin.run(ctx);
    assert.deepEqual(created[0], { type: 'infrastructure.netblock', data: { cidr: '8.8.8.0/24', network_name: 'GOGL' } });
    // No country in the ARIN answer, so none is invented.
    assert.equal('country_code' in created[0].data, false);

    const record = created[1];
    assert.equal(record.type, 'infrastructure.whois_record');
    assert.equal(record.data.subject, '8.8.8.0/24', 'the record describes the BLOCK, not the address');
    assert.equal(record.data.registrant, 'Google LLC');
    assert.equal(record.data.registrar, 'whois.arin.net');
    assert.equal(record.data.created_at, '2023-12-28T17:24:33-05:00', 'the registration event, not the last change');
    // Everything without a field of its own survives here, minus the registry's verbatim copy.
    assert.match(record.data.raw, /DIRECT ALLOCATION/);
    assert.equal(/"raw"/.test(record.data.raw), false, 'the registry payload is not nested inside itself');

    assert.deepEqual(edges, [
        { from: 'new-1', to: 'new-2', label: 'has whois' },
        { from: 'n1', to: 'new-1', label: 'within netblock' },
    ]);
    assert.deepEqual(updates, [{ id: 'n1', patch: { organization: 'Google LLC', version: 'ipv4' } }]);
    assert.match(out.summary, /whois\.arin\.net/);
}

// --- 1b. The contact email prefers the holder's own address over the registry's abuse desk ------
{
    const { ctx, created } = stubCtx(Object.fromEntries([ipNode('n1', '8.8.8.8')]), { '8.8.8.8': ARIN });
    await plugin.run(ctx);
    // ARIN's registrant carries no address, so the administrative/technical one is taken —
    // `abuse` is last, because a national registry answers with its own IRT for every block.
    assert.equal(created[1].data.registrant_email, 'arin-contact@google.com');
}

// --- 1c. `version` comes from the ADDRESS, so it is filled even on a barren answer -------------
{
    const { ctx, updates } = stubCtx(
        Object.fromEntries([ipNode('n1', '2001:4860:4860::8888')]),
        { '2001:4860:4860::8888': { query: '2001:4860:4860::8888', network: {}, entities: [], source: null } },
    );
    await plugin.run(ctx);
    assert.deepEqual(updates, [{ id: 'n1', patch: { version: 'ipv6' } }]);
}

// --- 2. APNIC with no national answer: the role contact must not become the organization -------
{
    const { ctx, created, updates } = stubCtx(
        Object.fromEntries([ipNode('n1', '1.201.0.1')]),
        { '1.201.0.1': APNIC_NO_NIR },
    );
    await plugin.run(ctx);
    assert.deepEqual(updates, [{ id: 'n1', patch: { country_code: 'KR', version: 'ipv4' } }], 'no "IP Manager" organization');
    // The allocation name is not lost — it belongs on the netblock, which is what a netname is.
    assert.equal(created[0].data.network_name, 'KINXINC-KR');
    assert.equal(created[0].data.country_code, 'KR');
}

// --- 2b. THE KR CASE THIS PACK EXISTS FOR -----------------------------------------------------
// KRNIC's own answer is more specific than the APNIC mirror and names the assignee. Taking the
// mirror would file the host under a range 256 times too large and under no organisation at all,
// which is precisely the coarseness the service's NIR fallback removes.
{
    const { ctx, created, updates } = stubCtx(
        Object.fromEntries([ipNode('n1', '1.201.0.1')]),
        { '1.201.0.1': APNIC },
    );
    const out = await plugin.run(ctx);
    assert.equal(created[0].data.cidr, '1.201.0.0/24', 'the assigned /24, not the mirrored /16');
    assert.equal(created[0].data.network_name, 'KINX');
    assert.deepEqual(updates, [{ id: 'n1', patch: { organization: 'KINX', country_code: 'KR', version: 'ipv4' } }]);
    // KRNIC's IRT address serves every Korean block; the holder's technical contact is the useful one.
    assert.equal(created[1].data.registrant_email, 'noc@kinx.net');
    assert.match(out.summary, /KRNIC/, 'the summary says which registry actually answered');
}

// --- 2c. A registrant, where one exists, outranks the national registry's netname ---------------
{
    const withBoth = { ...APNIC, entities: [{ roles: ['registrant'], name: 'KINX Inc.' }] };
    const { ctx, updates } = stubCtx(Object.fromEntries([ipNode('n1', '1.201.0.1')]), { '1.201.0.1': withBoth });
    await plugin.run(ctx);
    assert.equal(updates[0].patch.organization, 'KINX Inc.', 'an explicit registrant is the registry\'s own statement');
}

// --- 3. The update is a DELTA and never overwrites what the node already has -------------------
{
    const { ctx, updates } = stubCtx(
        Object.fromEntries([ipNode('n1', '8.8.8.8', { organization: 'corrected by hand', reverse_dns: 'dns.google' })]),
        { '8.8.8.8': ARIN },
    );
    await plugin.run(ctx);
    assert.deepEqual(updates, [{ id: 'n1', patch: { version: 'ipv4' } }], 'organization is left as the analyst wrote it');
}

// --- 4. One netblock per range, however many IPs land in it -----------------------------------
{
    const { ctx, created, edges } = stubCtx(
        Object.fromEntries([ipNode('n1', '8.8.8.8'), ipNode('n2', '8.8.8.9')]),
        { '8.8.8.8': ARIN, '8.8.8.9': { ...ARIN, query: '8.8.8.9' } },
    );
    await plugin.run(ctx);
    assert.equal(created.filter((c) => c.type === 'infrastructure.netblock').length, 1, 'the /24 is created once');
    assert.equal(created.filter((c) => c.type === 'infrastructure.whois_record').length, 1, 'and so is its record');
    assert.equal(edges.filter((e) => e.label === 'within netblock').length, 2, 'both IPs link to it');
}

// --- 5. A 401 stops the run and says why, rather than reporting an empty success ---------------
{
    const { ctx, created } = stubCtx(
        Object.fromEntries([ipNode('n1', '8.8.8.8'), ipNode('n2', '9.9.9.9')]),
        { '8.8.8.8': 401, '9.9.9.9': ARIN },
    );
    const out = await plugin.run(ctx);
    assert.match(out.summary, /session expired/i);
    assert.equal(created.length, 0, 'the rest of the selection is not spent on a dead session');
}

// --- 6. Nodes that are not IP addresses are skipped, not misread -------------------------------
{
    const { ctx, created } = stubCtx({ n1: { id: 'n1', type: 'infrastructure.domain', data: { domain_name: 'x.test' } } }, {});
    const out = await plugin.run(ctx);
    assert.equal(created.length, 0);
    assert.match(out.summary, /0 netblock/);
}

// --- 7. An app without ctx.service is told so, not left to look broken -------------------------
{
    const out = await plugin.run({ input: { selection: ['n1'] }, graph: {} });
    assert.match(out.summary, /does not offer Vineyard services/);
}

// --- 8. The two copies of the manifest agree --------------------------------------------------
{
    const json = JSON.parse(readFileSync(new URL('./plugins/vineyard-rdap.manifest.json', import.meta.url)));
    assert.equal(json.identifier, pack.identifier);
    assert.equal(json.version, pack.version);
    assert.equal(json.plugins.length, pack.plugins.length);
    const a = json.plugins[0];
    const b = plugin.manifest;
    assert.equal(a.identifier, b.identifier);
    assert.equal(a.version, b.version);
    assert.deepEqual(a.scopes, b.scopes, 'scopes are what the registry shows and the host grants');
    assert.deepEqual(a.io, b.io, 'io decides which nodes the run dialog offers');
    assert.deepEqual(
        a.io.produces.map((p) => p.name).sort(),
        ['netblock', 'whois_record'],
        'a produced type the manifest omits gets no icon, colour or label on the canvas',
    );
    assert.equal(a.name, 'Vineyard RDAP IP');
    // The registry validates the JSON manifest, so THAT is the copy whose entry must be resolvable.
    assert.deepEqual(a.scopes.services, ['rdap']);
    assert.equal('network' in a.scopes, false, 'a service pack declares no arbitrary egress');
}

console.log('vineyard-rdap ok: 13 scenarios');
