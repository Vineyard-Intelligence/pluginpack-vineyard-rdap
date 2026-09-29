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
        { handle: 'MI443-KR', roles: ['technical', 'administrative'], name: 'IP Manager', emails: ['noc@kinx.net'], phones: ['+82-2-580-4601'] },
        // KRNIC's incident-response team, returned for EVERY Korean block. Taking `abuse` first
        // would file the registry's own address as though it belonged to the holder — and since node
        // identity is type + label, it is not fifty nodes, it is ONE that collects an edge from every
        // Korean organisation the project ever touches.
        { handle: 'IRT-KRNIC-KR', roles: ['abuse'], name: 'IRT-KRNIC-KR', emails: ['hostmaster@nic.or.kr', 'hostmaster@nic.or.kr'] },
    ],
    source: 'whois.apnic.net',
    nir: {
        query: '1.201.0.1',
        nets: [
            { range: '1.201.0.0 - 1.201.255.255', cidr: '1.201.0.0/16', name: 'KINX', handle: 'KINXINC', country: 'KR' },
            {
                range: '1.201.0.0 - 1.201.0.255', cidr: '1.201.0.0/24', name: 'KINX', handle: 'KINXINC', country: 'KR',
                // The assignee's OWN contacts, which is the whole reason to prefer the national
                // registry: APNIC's mirror offers a contact called "IP Manager".
                contacts: {
                    admin: { name: 'IP Manager', email: 'noc@kinx.net', phone: '+82-2-580-4601' },
                    tech: { name: 'IP Manager', email: 'noc@kinx.net', phone: '+82-2-580-4600' },
                },
            },
        ],
    },
};
// RIPE holds 193.0.6.0/24 itself, so `abuse@ripe.net` on a TECHNICAL role really is the holder's —
// which is why the guard keys on abuse being the ONLY role rather than on the address.
// `+31205354444` has no separator after the dialing code, so its country code is unknowable.
const RIPE = {
    query: '193.0.6.139',
    network: { handle: '193.0.0.0 - 193.0.7.255', name: 'RIPE-NCC', cidr: '193.0.6.0/24', country: 'NL' },
    entities: [
        { handle: 'OPS4-RIPE', roles: ['technical'], name: 'RIPE NCC Operations', emails: ['abuse@ripe.net'], phones: ['+31 20 535 4444', '+31 20 535 4445'] },
        { handle: 'ORG-RIEN1-RIPE', roles: ['registrant'], name: 'RIPE NCC', emails: [], phones: ['+31205354444'] },
        { handle: 'OPS4-RIPE', roles: ['abuse'], name: 'RIPE NCC Operations', emails: ['abuse@ripe.net'], phones: [] },
    ],
    source: 'whois.ripe.net',
};
// LACNIC answers `+598  26042222#4401`. `#` is not in the phone type's validator, so the number
// would be refused outright for the sake of an extension.
const LACNIC = {
    query: '200.3.14.1',
    network: { handle: 'UY-LACN', name: 'LACNIC', cidr: '200.3.12.0/22' },
    entities: [
        { handle: 'UY-LACN-LACNIC', roles: ['registrant'], name: 'LACNIC', emails: [], phones: ['+598  26042222#4401'] },
        { handle: 'AIL', roles: ['administrative', 'technical', 'abuse'], name: 'Carlos M Martinez', emails: ['ipadmin@lacnic.net'], phones: [] },
    ],
    source: 'whois.lacnic.net',
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
    // `whois_record.subject` is declared as "the domain or IP this record describes (its identity)"
    // and `has_whois` runs from a domain or ip_address. A CIDR is neither, and a netblock is not a
    // permitted endpoint — the type is shared with domain WHOIS and a plugin does not get to
    // reinterpret it.
    assert.equal(record.data.subject, '8.8.8.8');
    assert.equal(record.data.registrant, 'Google LLC');
    assert.equal(record.data.created_at, '2023-12-28T17:24:33-05:00', 'the registration event, not the last change');
    // `registrar` means "sponsoring registrar", a domain concept. IP space has a REGISTRY, and
    // `whois.arin.net` is a server name — the field stays empty rather than holding a wrong answer.
    assert.equal('registrar' in record.data, false);
    // Everything without a field of its own survives here, minus the registry's verbatim copy.
    assert.match(record.data.raw, /DIRECT ALLOCATION/);
    assert.equal(/"raw"/.test(record.data.raw), false, 'the registry payload is not nested inside itself');

    assert.deepEqual(edges, [
        { from: 'n1', to: 'new-1', label: 'within netblock' },
        { from: 'n1', to: 'new-2', label: 'has whois' },
        // The organisation is `identity.organization`, and `identity.controls` is the only edge type
        // that takes one to a netblock (its `to` is `*`).
        { from: 'new-3', to: 'new-1', label: 'controls' },
        { from: 'new-3', to: 'new-4', label: 'owns' },
    ], 'has_whois runs FROM the ip_address, which is what the edge type declares');
    assert.deepEqual(created[2], { type: 'identity.organization', data: { name: 'Google LLC' } });
    assert.deepEqual(created[3], {
        type: 'identity.email_address',
        data: { email: 'arin-contact@google.com', display_name: 'Google LLC', domain: 'google.com' },
    });
    assert.equal(created.length, 4, 'network-abuse@google.com is ARIN abuse-only and gets no node');
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
    assert.equal(created.find((c) => c.type === 'infrastructure.whois_record').data.registrant_email, 'noc@kinx.net');
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
    assert.equal(edges.filter((e) => e.label === 'within netblock').length, 2, 'both IPs link to it');
    // One record PER SUBJECT, which for an IP record means per address. Honest duplication: the
    // per-range view is the netblock, and this type is keyed by the thing it describes.
    const subjects = created.filter((c) => c.type === 'infrastructure.whois_record').map((c) => c.data.subject);
    assert.deepEqual(subjects, ['8.8.8.8', '8.8.8.9']);
}

// --- 5. A 401 stops the run and says why, rather than reporting an empty success ---------------
{
    const { ctx, created } = stubCtx(
        Object.fromEntries([ipNode('n1', '8.8.8.8'), ipNode('n2', '9.9.9.9')]),
        { '8.8.8.8': 401, '9.9.9.9': ARIN },
    );
    // THROWN, not returned: the host paints a returned summary green and calls the run succeeded,
    // so a dead session would have read as an empty answer.
    await assert.rejects(() => plugin.run(ctx), /session expired/i);
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
    await assert.rejects(
        () => plugin.run({ input: { selection: ['n1'] }, graph: {} }),
        /does not offer Vineyard services/,
    );
}

// --- 7b. A run where EVERY lookup failed is a failure, not "0 netblocks" -----------------------
{
    const { ctx } = stubCtx(Object.fromEntries([ipNode('n1', '8.8.8.8'), ipNode('n2', '9.9.9.9')]), {});
    await assert.rejects(() => plugin.run(ctx), /every RDAP lookup failed/);
}
{
    // ...but a PARTIAL run still succeeds. Trading a silent failure for a false alarm is worse.
    const { ctx } = stubCtx(
        Object.fromEntries([ipNode('n1', '8.8.8.8'), ipNode('n2', '9.9.9.9')]),
        { '8.8.8.8': ARIN },
    );
    const out = await plugin.run(ctx);
    assert.match(out.summary, /1 lookup\(s\) failed/);
}

// --- 9. CONTACTS: the registry's own desk never becomes a node --------------------------------
{
    const { ctx, created, edges } = stubCtx(Object.fromEntries([ipNode('n1', '1.201.0.1')]), { '1.201.0.1': APNIC });
    await plugin.run(ctx);
    const emails = created.filter((c) => c.type === 'identity.email_address').map((c) => c.data.email);
    const phones = created.filter((c) => c.type === 'identity.phone_number').map((c) => c.data.number);
    const orgs = created.filter((c) => c.type === 'identity.organization').map((c) => c.data.name);

    assert.deepEqual(orgs, ['KINX'], "the national registry names the assignee; APNIC's mirror names a role mailbox");
    // THE POINT OF THE GUARD. Node identity is type + label, so hostmaster@nic.or.kr is not one node
    // per Korean lookup — it is ONE node that would collect an edge from every Korean organisation
    // in the project. It is KRNIC's incident-response desk and it connects nothing to anything.
    assert.equal(emails.includes('hostmaster@nic.or.kr'), false, "KRNIC's IRT is abuse-only and gets no node");
    assert.deepEqual(emails, ['noc@kinx.net'], 'named once by APNIC and twice by KRNIC, created once');
    assert.deepEqual(phones.sort(), ['+82-2-580-4600', '+82-2-580-4601']);
    assert.equal(created.find((c) => c.type === 'identity.phone_number').data.country_code, '82');
    assert.equal(
        created.find((c) => c.type === 'identity.email_address').data.display_name,
        'IP Manager',
        'the contact name rides along rather than becoming a person node nobody can verify',
    );
    const owns = edges.filter((e) => e.label === 'owns');
    assert.equal(owns.length, 3, 'one email + two phones, each owned by the organisation');
    assert.ok(owns.every((e) => e.from === edges.find((x) => x.label === 'controls').from));
}

// --- 9b. abuse-only is the test, not the address ----------------------------------------------
{
    const { ctx, created } = stubCtx(Object.fromEntries([ipNode('n1', '193.0.6.139')]), { '193.0.6.139': RIPE });
    await plugin.run(ctx);
    const emails = created.filter((c) => c.type === 'identity.email_address').map((c) => c.data.email);
    // RIPE holds this block itself, so abuse@ripe.net on a TECHNICAL role is genuinely the holder's.
    // Keying the guard on the address rather than on the roles would have thrown it away.
    assert.deepEqual(emails, ['abuse@ripe.net']);
    const phones = created.filter((c) => c.type === 'identity.phone_number');
    assert.deepEqual(phones.map((p) => p.data.number), ['+31 20 535 4444', '+31 20 535 4445', '+31205354444']);
    assert.deepEqual(phones.map((p) => p.data.country_code), ['31', '31', undefined],
        'a number with no separator after the code says nothing about whether it is 3, 31 or 312');
}

// --- 9c. An extension must not cost the whole number ------------------------------------------
{
    const { ctx, created } = stubCtx(Object.fromEntries([ipNode('n1', '200.3.14.1')]), { '200.3.14.1': LACNIC });
    await plugin.run(ctx);
    const phones = created.filter((c) => c.type === 'identity.phone_number').map((c) => c.data.number);
    // `+598  26042222#4401` — `#` is not in the type's validator, so creating it verbatim would be a
    // node the analyst never sees fail. The extension is dropped; the full string stays in `raw`.
    assert.deepEqual(phones, ['+598  26042222']);
    assert.deepEqual(
        created.filter((c) => c.type === 'identity.email_address').map((c) => c.data.email),
        ['ipadmin@lacnic.net'],
        'Carlos also holds admin/technical, so he is not abuse-only',
    );
}

// --- 9c-bis. Registry text is third-party and goes into VALIDATED fields ----------------------
{
    // `identity.email_address` validates ^[^@\s]+@[^@\s]+\.[^@\s]+$. A create that fails a
    // validator is a node that silently never appears, with no error the analyst ever sees — so the
    // check happens here, before it becomes graph data. Same reason the phone number is checked.
    const malformed = {
        query: '6.6.6.6',
        network: { cidr: '6.6.6.0/24' },
        entities: [
            {
                handle: 'H', roles: ['registrant'], name: 'Sixes Ltd',
                emails: ['noc@sixes', 'not an email', '', 'real@sixes.test'],
                phones: ['12', 'call us', '+1-555-0100'],
            },
        ],
        source: 'whois.test',
    };
    const { ctx, created } = stubCtx(Object.fromEntries([ipNode('n1', '6.6.6.6')]), { '6.6.6.6': malformed });
    await plugin.run(ctx);
    assert.deepEqual(
        created.filter((c) => c.type === 'identity.email_address').map((c) => c.data.email),
        ['real@sixes.test'],
        'noc@sixes has an @ and still fails the type validator — a bare hostname is not a domain',
    );
    assert.deepEqual(
        created.filter((c) => c.type === 'identity.phone_number').map((c) => c.data.number),
        ['+1-555-0100'],
        'too short and non-numeric both fail the phone validator',
    );
}

// --- 9c-ter. The FIRST name for an address wins, so a later mention cannot rewrite it ----------
{
    const twoNames = {
        query: '7.7.7.7',
        network: { cidr: '7.7.7.0/24', country: 'KR' },
        entities: [{ handle: 'A', roles: ['registrant'], name: 'Sevens', emails: ['ops@sevens.test'] }],
        source: 'whois.test',
        nir: {
            nets: [{
                cidr: '7.7.7.0/24', name: 'Sevens', country: 'KR',
                contacts: { admin: { name: 'Night shift', email: 'ops@sevens.test' } },
            }],
        },
    };
    const { ctx, created } = stubCtx(Object.fromEntries([ipNode('n1', '7.7.7.7')]), { '7.7.7.7': twoNames });
    await plugin.run(ctx);
    const mail = created.filter((c) => c.type === 'identity.email_address');
    assert.equal(mail.length, 1, 'one address named twice is one node');
    assert.equal(mail[0].data.display_name, 'Sevens', 'the first mention holds the name');
}

// --- 9c-quater. A hostile or broken registry answer costs a BOUNDED number of nodes -----------
{
    const flood = {
        query: '4.4.4.4',
        network: { cidr: '4.4.4.0/24' },
        entities: [{
            handle: 'F', roles: ['registrant'], name: 'Flood Ltd',
            emails: Array.from({ length: 300 }, (_, i) => `c${i}@flood.test`),
            phones: Array.from({ length: 300 }, (_, i) => `+1-555-${String(i).padStart(4, '0')}`),
        }],
        source: 'whois.test',
    };
    const { ctx, created } = stubCtx(Object.fromEntries([ipNode('n1', '4.4.4.4')]), { '4.4.4.4': flood });
    await plugin.run(ctx);
    // The service is ours; the DATA inside it is five registries'. 600 staged nodes from one
    // lookup is a review dialog nobody reads, whether the cause is malice or a parser bug.
    assert.equal(created.filter((c) => c.type === 'identity.email_address').length, 8);
    assert.equal(created.filter((c) => c.type === 'identity.phone_number').length, 8);
}

// --- 9d. No holder means no contacts. An address with nothing to attach it to is not an answer --
{
    const bare = { query: '5.5.5.5', network: { cidr: '5.5.5.0/24' }, entities: [
        { handle: 'X', roles: ['abuse'], name: 'Abuse desk', emails: ['abuse@registry.test'] },
    ], source: 'whois.test' };
    const { ctx, created } = stubCtx(Object.fromEntries([ipNode('n1', '5.5.5.5')]), { '5.5.5.5': bare });
    await plugin.run(ctx);
    assert.equal(created.some((c) => c.type.startsWith('identity.')), false);
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
        ['email_address', 'netblock', 'organization', 'phone_number', 'whois_record'],
        'a produced type the manifest omits gets no icon, colour or label on the canvas',
    );
    assert.equal(a.name, 'Vineyard RDAP IP');
    // The registry validates the JSON manifest, so THAT is the copy whose entry must be resolvable.
    assert.deepEqual(a.scopes.services, ['rdap']);
    assert.equal('network' in a.scopes, false, 'a service pack declares no arbitrary egress');
}

console.log('vineyard-rdap ok: 22 scenarios');
