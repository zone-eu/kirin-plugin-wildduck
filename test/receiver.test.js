'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const { Readable, Writable } = require('node:stream');
const crypto = require('node:crypto');

process.env.DISABLE_WILD_CONFIG = 'true';

// Isolate dependency mocks without changing the process-wide require cache.
function loadModule(file, mocks = {}, suffix = '') {
    const filename = path.resolve(__dirname, '..', file);
    const localRequire = createRequire(filename);
    const module = { exports: {} };
    const evaluate = vm.compileFunction(fs.readFileSync(filename, 'utf8') + suffix, ['require', 'module', 'exports'], { filename });

    evaluate(name => (Object.hasOwn(mocks, name) ? mocks[name] : localRequire(name)), module, module.exports);

    return module.exports;
}

function receiver(mocks = {}, config = {}) {
    const Plugin = loadModule('index.js', mocks, '\nmodule.exports.TestPlugin = KirinPluginWildduck;').TestPlugin;
    const logs = [];
    const plugin = new Plugin({
        options: {},
        config,
        logger: { verbose() {}, info() {}, notice() {}, error() {} },
        manager: { options: { getConnection: session => session.connection } },
        addHook() {}
    });

    plugin.loggelf = entry => logs.push(entry);

    return { plugin, logs };
}

function connection(raw) {
    const headers = new Map([
        ['subject', ['=?UTF-8?Q?Hello_=C3=B5?=']],
        ['from', ['=?UTF-8?Q?Sender_=C3=B5?= <sender@example.com>']],
        ['to', ['alice@example.net']],
        ['content-type', ['text/plain']]
    ]);
    const authResults = [];

    return {
        authResults,
        remote: { ip: '8.8.8.8', is_private: false },
        local: { host: 'mx.example.net' },
        hello: { host: 'mail.example.com' },
        session: { transmissionType: 'ESMTPS' },
        results: new Map(),
        auth_results: info => authResults.push(info),
        loginfo() {},
        lognotice() {},
        logdebug() {},
        logerror() {},
        transaction: {
            uuid: 'queue-id',
            notes: { sender: 'sender@example.com' },
            results: new Map(),
            rcpt_to: [{ address: () => 'alice@example.net' }, { address: 'bob@example.net' }],
            header: {
                get: name => headers.get(name.toLowerCase())?.[0] || '',
                get_all: name => headers.get(name.toLowerCase()) || []
            },
            add_header: (name, value) => headers.set(name.toLowerCase(), [...(headers.get(name.toLowerCase()) || []), value]),
            add_leading_header: (name, value) => headers.set(name.toLowerCase(), [value, ...(headers.get(name.toLowerCase()) || [])]),
            remove_header: name => headers.delete(name.toLowerCase()),
            getSourceStream: () => Readable.from([raw || Buffer.from('From: sender@example.com\r\n\r\nHello\r\n')]),
            getMessageChunks: () => [raw || Buffer.from('From: sender@example.com\r\n\r\nHello\r\n')],
            getMessageSize: () => (raw || Buffer.from('From: sender@example.com\r\n\r\nHello\r\n')).length
        }
    };
}

const settings = { 'const:max:storage': 1000000, 'const:max:forwards': 100 };

function database(user) {
    return {
        settingsHandler: { getMulti: async () => settings },
        userHandler: {
            resolveAddress: (address, options, done) => done(null, { user: user?._id, address }),
            get: (id, projection, done) =>
                done(null, Object.fromEntries(Object.entries(user).filter(([key]) => key === '_id' || projection[key])))
        },
        messageHandler: { notifier: {} },
        redis: {},
        database: {}
    };
}

function disableLimits(plugin) {
    plugin.ttlcounter = (key, increment, limit, window, done) => done(null, { success: true });
}

test('recipient resolution carries S/MIME settings into message storage', async () => {
    const user = {
        _id: 'alice-id',
        address: 'alice@example.net',
        encryptMessages: true,
        encryptForwarded: true,
        smimeCerts: ['certificate'],
        smimeCipher: 'AES-GCM',
        smimeKeyTransport: 'OAEP'
    };

    const { plugin, logs } = receiver();
    plugin.db = database(user);
    disableLimits(plugin);

    const conn = connection();

    await plugin.smtpRcptTo({ address: user.address }, { connection: conn });

    const resolved = conn.transaction.notes.targets.users.get(user._id);
    assert.deepEqual({ ...resolved.userData }, user);
    assert.equal(require('@zone-eu/wildduck/lib/tools').getUserEncryptionKey(resolved.userData).type, 'smime');

    let stored;
    plugin.filterHandler = {
        storeMessage: async (recipient, options) => {
            stored = { recipient, options };

            return { response: { response: 'stored', size: 100 } };
        }
    };

    const result = await new Promise(resolve => plugin.hook_queue((...args) => resolve(args), conn));

    assert.equal(result[0], 'OK');
    assert.equal(stored.recipient.smimeCipher, user.smimeCipher);
    assert.equal(stored.recipient.smimeKeyTransport, user.smimeKeyTransport);
    assert.equal(stored.options.recipient, user.address);
    assert.equal(logs.find(entry => entry._mail_action === 'rcpt_to')._subject, 'Hello õ');
});

test('MAIL logs sender and private-client SPF with the installed mailauth', async () => {
    const { plugin, logs } = receiver();
    plugin.db = database();
    plugin.resolver = async () => [];

    const conn = connection();
    conn.remote.is_private = true;
    conn.remote.ip = '127.0.0.1';

    await plugin.smtpMailFrom({ address: 'new@example.com' }, { connection: conn });

    assert.equal(conn.transaction.notes.sender, 'new@example.com');
    assert.equal(conn.transaction.notes.spfResult.status.result, 'softfail');
    assert.equal(logs[0]._mail_action, 'mail_from');
    assert.equal(logs[0]._from, 'new@example.com');
});

test('unknown recipient rejects with SMTP status and logs only that recipient before DATA', async () => {
    const { plugin, logs } = receiver();
    plugin.db = database();

    const conn = connection();
    conn.transaction.header = false;

    await assert.rejects(
        plugin.smtpRcptTo({ address: 'missing@example.net' }, { connection: conn }),
        err => err.responseCode === 550 && /5.1.1/.test(err.message)
    );

    const deny = logs.filter(entry => entry._mail_action === 'deny');

    assert.equal(deny.length, 1);
    assert.equal(deny[0]._to, 'missing@example.net');
    assert.equal(deny[0]._reject_code, 'NO_SUCH_USER');
    assert.equal(deny[0]._subject, '');
});

test('DATA rejection logs every recipient with decoded headers and user IDs', async () => {
    const { plugin, logs } = receiver({
        './lib/auth': { hookDataPost: async () => {} }
    });
    plugin.db = database();

    const conn = connection();
    await plugin.init_wildduck_transaction(conn);
    conn.transaction.notes.targets.users.set('alice-id', {
        recipient: 'alice@example.net',
        userData: { _id: 'alice-id' }
    });
    conn.transaction.results.set('rspamd', {
        symbols: { DMARC_POLICY_REJECT: 10 }
    });
    plugin.rspamd = plugin.cfg.rspamd;

    await assert.rejects(plugin.smtpData({}, { connection: conn }), err => err.responseCode === 550);

    assert.equal(logs.length, 2);
    assert.equal(logs[0]._to, 'alice@example.net');
    assert.equal(logs[1]._to, 'bob@example.net');
    assert.equal(logs[0]._user, 'alice-id');
    assert.equal(logs[0]._subject, 'Hello õ');
    assert.equal(logs[0]._header_from_name, 'Sender õ');
    assert.equal(logs[0]._reject_code, 'DMARC_POLICY_REJECT');
});

test('initialization failures return an SMTP error instead of leaving MAIL pending', async () => {
    const { plugin, logs } = receiver();
    plugin.init_wildduck_transaction = async () => {
        throw new Error('database unavailable');
    };

    const conn = connection();
    conn.transaction.header = false;

    await assert.rejects(
        plugin.smtpMailFrom({ address: 'sender@example.com' }, { connection: conn }),
        err => err.responseCode === 450 && err.message === 'database unavailable'
    );

    assert.equal(logs[0]._mail_action, 'deny');
});

test('APNs attaches to the delivery notifier with absolute paths and closes at shutdown', async () => {
    let options;
    let closed = false;
    let quit = false;

    const db = database();
    db.redis.quit = async () => {
        quit = true;
    };

    const { plugin } = receiver(
        {
            './lib/db': { connect: (redis, config, done) => done(null, db) },
            '@zone-eu/wildduck/lib/apn-client': {
                get: value => {
                    options = value;

                    return {
                        close: () => {
                            closed = true;
                        }
                    };
                }
            },
            '@zone-eu/wildduck/lib/counters': () => ({ ttlcounter() {} }),
            '@zone-eu/wildduck/lib/maildropper': class {},
            '@zone-eu/wildduck/lib/filter-handler': class {},
            '@zone-eu/wildduck/lib/bimi-handler': { create: () => ({}) }
        },
        {
            aps: {
                enabled: true,
                sandbox: true,
                topic: 'push.topic',
                certPath: 'config/apns.pem',
                keyPath: '/tmp/apns.key'
            }
        }
    );

    plugin.open_database();

    assert.equal(options.database, db.database);
    assert.equal(options.config.certPath, path.resolve('config/apns.pem'));
    assert.equal(options.config.keyPath, '/tmp/apns.key');
    assert.equal(options.config.sandbox, true);

    await plugin.shutdown();

    assert.equal(closed, true);
    assert.equal(quit, true);
});

test('S/MIME startup detects available and disabled PKCS#1 v1.5 encryption', () => {
    for (const available of [true, false]) {
        const smime = {};
        const { plugin } = receiver({
            '@zone-eu/smime-js': smime,
            crypto: {
                generateKeyPairSync: () => ({ publicKey: 'key' }),
                constants: crypto.constants,
                publicEncrypt: () => {
                    if (!available) throw new Error('disabled');

                    return Buffer.from('encrypted');
                }
            }
        });

        plugin.initializeSmime();

        assert.equal(smime.pkcs1v15Available, available);
    }
});

test('forwarding preserves every message chunk and logs the decoded subject', async () => {
    const { plugin, logs } = receiver();
    const conn = connection();
    plugin.db = database();
    await plugin.init_wildduck_transaction(conn);
    conn.transaction.getMessageChunks = () => [Buffer.from('headers\r\n\r\n'), Buffer.from('body')];
    conn.transaction.getMessageSize = () => 15;
    conn.transaction.notes.targets.forwards.set('target', {
        type: 'mail',
        value: 'target@example.net'
    });

    let forwarded = Buffer.alloc(0);
    plugin.maildrop = {
        push: (mail, done) =>
            new Writable({
                write(chunk, encoding, next) {
                    forwarded = Buffer.concat([forwarded, chunk]);
                    next();
                },
                final(next) {
                    done(null, { id: 'forward-id' });
                    next();
                }
            })
    };

    await new Promise(resolve => plugin.hook_queue(resolve, conn));

    assert.equal(forwarded.toString(), 'headers\r\n\r\nbody');
    assert.equal(logs.find(entry => entry._queued === 'yes')._subject, 'Hello õ');
});

test('installed mailauth verifies signed mail through SPF, DKIM, ARC, DMARC and BIMI', async () => {
    const { dkimSign } = require('mailauth');
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048
    });
    const raw = Buffer.from(
        'From: sender@example.com\r\nTo: alice@example.net\r\nSubject: Hello\r\nContent-Type: text/plain\r\n\r\nHello world\r\n'
    );

    const signed = await dkimSign(raw, {
        signatureData: [
            {
                signingDomain: 'example.com',
                selector: 'test',
                privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' })
            }
        ]
    });

    assert.equal(signed.errors.length, 0);

    const conn = connection(Buffer.concat([Buffer.from(signed.signatures), raw]));
    const { plugin, logs } = receiver();
    const publicDer = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    plugin.resolver = async (name, type) => {
        assert.equal(type, 'TXT');

        const records = {
            'example.com': 'v=spf1 ip4:8.8.8.8 -all',
            'test._domainkey.example.com': `v=DKIM1; k=rsa; p=${publicDer}`,
            '_dmarc.example.com': 'v=DMARC1; p=reject',
            'default._bimi.example.com': 'v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem'
        };

        if (records[name]) return [[records[name]]];

        const err = new Error('No DNS record');
        err.code = 'ENODATA';

        throw err;
    };
    plugin.bimiHandler = {
        getInfo: async () => ({
            _id: 'bimi-id',
            type: 'authority',
            vmc: { logoFile: 'a'.repeat(120) }
        })
    };

    const auth = require('../lib/auth');
    await auth.hookMail(plugin, conn, [{ address: 'sender@example.com' }]);
    await auth.hookDataPost(conn.transaction.getSourceStream(), plugin, conn);

    const notes = conn.transaction.notes;

    assert.equal(notes.spfResult.status.result, 'pass');
    assert.equal(notes.dkimResult.results[0].status.result, 'pass');
    assert.equal(notes.arcResult.status.result, 'none');
    assert.equal(notes.dmarcResult.status.result, 'pass');
    assert.equal(notes.bimiResult.status.result, 'pass');
    assert.equal(notes.bimi, 'bimi-id');
    assert.equal(conn.authResults.filter(info => info.startsWith('dkim=')).length, 1);
    assert.match(
        conn.authResults.find(info => info.startsWith('bimi=')),
        /policy.authority=pass/
    );
    assert.ok(conn.transaction.header.get('BIMI-Indicator').includes('\r\n '));
    assert.equal(logs.find(entry => entry._mail_action === 'dkim_verify')._subject, 'Hello õ');
});

for (const outcome of ['valid', 'missing', 'invalid']) {
    test(`BIMI authority ${outcome} reports its validation outcome and diagnostics`, async () => {
        const failure = Object.assign(new Error('VMC validation failed'), {
            code: 'InvalidVMC',
            source: 'authority',
            details: { url: 'https://example.com/vmc.pem', reason: 'expired' }
        });

        const auth = loadModule('lib/auth.js', {
            'mailauth/lib/dkim/verify': {
                dkimVerify: async () => ({
                    headerFrom: 'example.com',
                    headers: { parsed: [] },
                    results: []
                })
            },
            'mailauth/lib/dmarc': {
                dmarc: async () => ({ status: { result: 'pass' } })
            },
            'mailauth/lib/bimi': {
                bimi: async () => ({
                    status: { result: 'pass', header: { d: 'example.com' } },
                    info: 'bimi=pass policy.authority=none'
                })
            }
        });

        const { plugin, logs } = receiver();
        plugin.bimiHandler = {
            getInfo: async () => {
                if (outcome === 'invalid') throw failure;

                return outcome === 'missing' ? false : { _id: 'bimi-id' };
            }
        };

        const conn = connection();
        conn.transaction.add_header('BIMI-Indicator', 'forged');
        conn.transaction.add_header('BIMI-Location', 'forged');

        await auth.hookDataPost(conn.transaction.getSourceStream(), plugin, conn);

        const info = conn.authResults.find(entry => entry.startsWith('bimi='));

        assert.match(info, new RegExp(`policy.authority=${{ valid: 'pass', missing: 'none', invalid: 'fail' }[outcome]}`));
        assert.equal(conn.transaction.header.get('BIMI-Indicator'), '');
        assert.equal(conn.transaction.header.get('BIMI-Location'), '');

        if (outcome === 'valid') assert.equal(conn.transaction.notes.bimi, 'bimi-id');

        if (outcome === 'missing') assert.equal(logs[0]._has_bimi, 'no');

        if (outcome === 'invalid') {
            assert.equal(logs[0]._bimi_url, failure.details.url);
            assert.equal(logs[0]._err, 'InvalidVMC');
            assert.equal(logs[0]._bimi_source, 'authority');
            assert.equal(JSON.parse(logs[0]._bimi_data).reason, 'expired');
            assert.equal(failure.details.url, 'https://example.com/vmc.pem');
        }
    });
}

test('unverified BIMI headers are removed even when DKIM verification fails', async () => {
    const auth = loadModule('lib/auth.js', {
        'mailauth/lib/dkim/verify': {
            dkimVerify: async () => {
                throw new Error('Malformed message');
            }
        }
    });
    const { plugin } = receiver();
    const conn = connection();
    conn.transaction.add_header('BIMI-Indicator', 'forged');
    conn.transaction.add_header('BIMI-Location', 'forged');

    await auth.hookDataPost(conn.transaction.getSourceStream(), plugin, conn);

    assert.equal(conn.transaction.header.get('BIMI-Indicator'), '');
    assert.equal(conn.transaction.header.get('BIMI-Location'), '');
});

test('resolved S/MIME settings encrypt and decrypt mail using WildDuck 1.55.1', async () => {
    const forge = createRequire(require.resolve('@zone-eu/wildduck/package.json'))('node-forge');
    const MessageHandler = require('@zone-eu/wildduck/lib/message-handler');
    const { execFileSync } = require('node:child_process');

    const { plugin } = receiver();
    plugin.initializeSmime();

    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048
    });
    const privatePem = privateKey.export({ type: 'pkcs1', format: 'pem' });

    const cert = forge.pki.createCertificate();
    cert.publicKey = forge.pki.publicKeyFromPem(publicKey.export({ type: 'spki', format: 'pem' }));
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date(Date.now() - 60000);
    cert.validity.notAfter = new Date(Date.now() + 86400000);
    cert.setSubject([{ name: 'commonName', value: 'alice@example.net' }]);
    cert.setIssuer(cert.subject.attributes);
    cert.setExtensions([{ name: 'keyUsage', keyEncipherment: true }]);
    cert.sign(forge.pki.privateKeyFromPem(privatePem), forge.md.sha256.create());

    const certPem = forge.pki.certificateToPem(cert);
    const user = {
        _id: 'alice-id',
        address: 'alice@example.net',
        encryptMessages: true,
        smimeCerts: [certPem],
        smimeCipher: 'AES-CBC',
        smimeKeyTransport: 'OAEP'
    };
    plugin.db = database(user);
    disableLimits(plugin);

    const conn = connection();

    await plugin.smtpRcptTo({ address: user.address }, { connection: conn });

    const resolved = conn.transaction.notes.targets.users.get(user._id).userData;
    const key = require('@zone-eu/wildduck/lib/tools').getUserEncryptionKey(resolved);

    const handler = Object.create(MessageHandler.prototype);
    handler.loggelf = () => {};
    const raw = Buffer.from(
        'From: sender@example.com\r\nTo: alice@example.net\r\nSubject: Private\r\nContent-Type: text/plain\r\n\r\nSecret message\r\n'
    );

    const result = await handler.encryptMessageAsync(key, Buffer.from(raw));

    assert.equal(result.type, 'smime');
    assert.match(result.raw.toString(), /application\/pkcs7-mime/);
    assert.equal(result.raw.includes('Secret message'), false);

    // OpenSSL independently verifies that encryption preserves the complete message.
    const dir = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'kirin-smime-'));

    try {
        fs.writeFileSync(path.join(dir, 'cert.pem'), certPem);
        fs.writeFileSync(path.join(dir, 'key.pem'), privatePem, { mode: 0o600 });
        fs.writeFileSync(path.join(dir, 'message.eml'), result.raw);

        const decrypted = execFileSync(
            '/usr/bin/openssl',
            [
                'cms',
                '-decrypt',
                '-in',
                path.join(dir, 'message.eml'),
                '-recip',
                path.join(dir, 'cert.pem'),
                '-inkey',
                path.join(dir, 'key.pem')
            ],
            { timeout: 10000, stdio: ['ignore', 'pipe', 'pipe'] }
        );

        assert.deepEqual(decrypted, raw);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});
