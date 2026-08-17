'use strict';

process.env.DISABLE_WILD_CONFIG = 'true';

const os = require('os');
const dns = require('dns');
const deepExtend = require('deep-extend');
const db = require('./lib/db');
const DSN = require('./lib/dsn');
const ObjectId = require('mongodb').ObjectId;
const punycode = require('punycode.js');
const SRS = require('srs.js');
const counters = require('@zone-eu/wildduck/lib/counters');
const tools = require('@zone-eu/wildduck/lib/tools');
const Maildropper = require('@zone-eu/wildduck/lib/maildropper');
const FilterHandler = require('@zone-eu/wildduck/lib/filter-handler');
const BimiHandler = require('@zone-eu/wildduck/lib/bimi-handler');
const autoreply = require('@zone-eu/wildduck/lib/autoreply');
const wdErrors = require('@zone-eu/wildduck/lib/errors');
const Gelf = require('gelf');
const addressparser = require('nodemailer/lib/addressparser');
const libmime = require('libmime');
const { promisify } = require('util');
const wildduckPlugins = require('@zone-eu/wildduck/lib/plugins');
const { hookMail: authHookMail, hookDataPost: authHookDataPost } = require('./lib/auth');

const OK = 'OK';
const DENY = 'DENY';
const DENYSOFT = 'DENYSOFT';

const defaultSpamRejectMessage =
    'Our system has detected that this message is likely unsolicited mail.\nTo reduce the amount of spam this message has been blocked.';

const runSequentially = async (items, handler, index = 0) => {
    if (!items || index >= items.length) {
        return;
    }

    await handler(items[index], index);
    return runSequentially(items, handler, index + 1);
};

const DEFAULT_CONFIG = {
    redis: {
        port: 6379,
        host: '127.0.0.1',
        db: 3
    },
    mongo: {
        url: 'mongodb://127.0.0.1:27017/wildduck',
        sender: 'zone-mta'
    },
    sender: {
        enabled: true,
        zone: 'default',
        gfs: 'mail',
        collection: 'zone-queue'
    },
    srs: {
        secret: 'secret value'
    },
    attachments: {
        type: 'gridstore',
        bucket: 'attachments',
        decodeBase64: true
    },
    limits: {
        windowSize: 3600,
        rcptIp: 100,
        rcptWindowSize: 60,
        rcpt: 60
    },
    gelf: {
        enabled: false,
        component: 'mx',
        options: {
            graylogPort: 12201,
            graylogHostname: '127.0.0.1',
            connection: 'lan'
        }
    },
    rspamd: {
        forwardSkip: 10,
        blacklist: ['DMARC_POLICY_REJECT'],
        softlist: ['RBL_ZONE'],
        responses: {
            DMARC_POLICY_REJECT: "Unauthenticated email from {host} is not accepted due to domain's DMARC policy",
            RBL_ZONE: '[{host}] was found from Zone RBL'
        }
    },
    auth: {
        dns: {
            maxLookups: 50
        },
        minBitLength: 1024
    },
    originalRcptHeader: 'X-Zone-Original-Rcpt'
};

const smtpMessage = message => {
    if (!message) {
        return '';
    }

    if (typeof message === 'string') {
        return message;
    }

    return message.reply || message.message || message.msg || message.toString();
};

const createSmtpError = (action, message) => {
    if (message instanceof Error) {
        if (!message.responseCode) {
            message.responseCode = action === DENYSOFT ? 450 : 550;
        }
        return message;
    }

    const error = new Error(smtpMessage(message) || 'Temporary failure');
    error.responseCode = message?.code || (action === DENYSOFT ? 450 : 550);
    return error;
};

const sanitizeConfig = config => {
    const sanitized = deepExtend({}, config || {});
    delete sanitized.enabled;
    delete sanitized.ordering;
    return sanitized;
};

const resolveHookResult = (connection, resolve, reject, args) => {
    const [action, message] = args;

    if (!action || action === OK) {
        if (message && connection.transaction) {
            connection.transaction.responseMessage = smtpMessage(message);
        }
        return resolve(message);
    }

    if (action instanceof Error) {
        return reject(action);
    }

    if (action === DENY || action === DENYSOFT) {
        return reject(createSmtpError(action, message));
    }

    return reject(createSmtpError(DENYSOFT, message));
};

const wrapAddress = address => {
    if (!address || typeof address.address === 'function') {
        return address;
    }

    const addressValue = typeof address.address === 'string' ? address.address : '';
    const atPos = addressValue.lastIndexOf('@');

    return {
        ...address,
        user: atPos >= 0 ? addressValue.substring(0, atPos) : addressValue,
        host: atPos >= 0 ? addressValue.substring(atPos + 1) : '',
        address: () => addressValue
    };
};

DSN.rcpt_too_fast = () =>
    DSN.create(
        450,
        'The user you are trying to contact is receiving mail at a rate that\nprevents additional messages from being delivered. Please resend your\nmessage at a later time. If the user is able to receive mail at that\ntime, your message will be delivered.',
        2,
        1
    );

DSN.mbox_full_554 = () => DSN.create(554, 'Mailbox full', 2, 2);

class ZoneMxPluginWildduck {
    constructor(plugin) {
        this.plugin = plugin;
        this.title = plugin.options.title || 'ZoneMxPluginWildduck';
        this.cfg = deepExtend({}, DEFAULT_CONFIG, sanitizeConfig(plugin.config));
        this.resolver = async (name, rr) => await dns.promises.resolve(name, rr);
        this.db = false;
        this.gelf = false;
        this.maildrop = false;
        this.filterHandler = false;
        this.bimiHandler = false;
        this._dbRetryTimer = false;
    }

    logdebug(message, ...args) {
        this.plugin.logger.verbose(this.title, message, ...args);
    }

    loginfo(message, ...args) {
        this.plugin.logger.info(this.title, message, ...args);
    }

    lognotice(message, ...args) {
        this.plugin.logger.notice(this.title, message, ...args);
    }

    logerror(message, ...args) {
        this.plugin.logger.error(this.title, message, ...args);
    }

    logcrit(message, ...args) {
        this.plugin.logger.error(this.title, message, ...args);
    }

    async init() {
        this.plugin.addHook('smtp:mail_from', this.smtpMailFrom.bind(this));
        this.plugin.addHook('smtp:rcpt_to', this.smtpRcptTo.bind(this));
        this.plugin.addHook('smtp:data', this.smtpData.bind(this));
        this.plugin.addHook('shutdown', this.shutdown.bind(this));

        this.open_database();
    }

    async shutdown() {
        clearTimeout(this._dbRetryTimer);
        if (this.db?.redis?.quit) {
            try {
                await this.db.redis.quit();
            } catch {
                // ignore
            }
        }
    }

    getConnection(session) {
        const getConnection = this.plugin.manager?.options?.getConnection;
        if (typeof getConnection !== 'function') {
            throw new Error('Kirin connection resolver is not configured');
        }
        return getConnection(session);
    }

    smtpMailFrom(address, session) {
        const connection = this.getConnection(session);
        return new Promise((resolve, reject) => {
            this.hook_mail((...args) => resolveHookResult(connection, resolve, reject, args), connection, [wrapAddress(address)]);
        });
    }

    smtpRcptTo(address, session) {
        const connection = this.getConnection(session);
        return new Promise((resolve, reject) => {
            this.hook_rcpt((...args) => resolveHookResult(connection, resolve, reject, args), connection, [wrapAddress(address)]);
        });
    }

    async smtpData(_envelope, session) {
        const connection = this.getConnection(session);
        await this.init_wildduck_transaction(connection);
        await authHookDataPost(connection.transaction.getSourceStream(), this, connection);

        return new Promise((resolve, reject) => {
            this.hook_queue((...args) => resolveHookResult(connection, resolve, reject, args), connection);
        });
    }

    open_database() {
        this.srsRewriter = new SRS({
            secret: (this.cfg.srs && this.cfg.srs.secret) || 'secret'
        });

        this.rspamd = this.cfg.rspamd || {};
        this.rspamd.forwardSkip = Number(this.rspamd.forwardSkip) || Number(this.cfg.spamScoreForwarding) || 0;
        this.rspamd.blacklist = [].concat(this.rspamd.blacklist || []);
        this.rspamd.softlist = [].concat(this.rspamd.softlist || []);
        this.rspamd.responses = this.rspamd.responses || {};

        this.hostname = (this.cfg.gelf && this.cfg.gelf.hostname) || os.hostname();
        this.gelf =
            this.cfg.gelf && this.cfg.gelf.enabled
                ? new Gelf(this.cfg.gelf.options)
                : {
                    emit: (level, message) => {
                        this.loginfo('GELF ' + JSON.stringify(message));
                    }
                };
        wdErrors.setGelf(this.gelf);

        this.loggelf = message => {
            if (typeof message === 'string') {
                message = {
                    short_message: message
                };
            }
            message = message || {};

            const component = (this.cfg.gelf && this.cfg.gelf.component) || 'mx';
            if (!message.short_message || message.short_message.indexOf(component.toUpperCase()) !== 0) {
                message.short_message = component.toUpperCase() + ' ' + (message.short_message || '');
            }

            message.facility = component;
            message.host = this.hostname;
            message.timestamp = Date.now() / 1000;
            message._component = component;
            message._interface = message._interface || 'mx';

            Object.keys(message).forEach(key => {
                if (!message[key]) {
                    delete message[key];
                }
            });

            this.gelf.emit('gelf.log', message);
        };

        const createConnection = done => {
            db.connect(false, this.cfg, (err, database) => {
                if (err) {
                    return done(err);
                }
                this.db = database;
                this.ttlcounter = counters(database.redis).ttlcounter;
                this.ttlcounterAsync = promisify(this.ttlcounter);

                this.db.messageHandler.loggelf = message => this.loggelf(message);
                this.db.userHandler.loggelf = message => this.loggelf(message);

                this.maildrop = new Maildropper({ db: database, ...this.cfg.sender });

                this.filterHandler = new FilterHandler({
                    db: database,
                    sender: this.cfg.sender,
                    messageHandler: this.db.messageHandler,
                    loggelf: message => this.loggelf(message)
                });

                if (this.cfg.plugins && this.cfg.plugins.pluginsPath && this.cfg.plugins.conf) {
                    const config = deepExtend({}, this.cfg);
                    config.log = this.cfg.gelf;

                    wildduckPlugins.init({ context: 'receiver', config });
                    wildduckPlugins.handler.load(() => {
                        wildduckPlugins.handler.runHooks('init', [], () => { });
                    });
                }

                this.bimiHandler = BimiHandler.create({
                    database: database.database,
                    loggelf: message => this.loggelf(message)
                });

                done();
            });
        };

        let returned = false;
        const tryCreateConnection = () => {
            createConnection(err => {
                if (err) {
                    if (!returned) {
                        this.logcrit('Database connection failed. %s', err.message);
                        returned = true;
                    }
                    this._dbRetryTimer = setTimeout(tryCreateConnection, 2 * 1000);
                    return;
                }

                this.loginfo('Database connection opened');
            });
        };

        tryCreateConnection();
    }

    normalize_address(address) {
        if (/^SRS\d+=/i.test(address.user)) {
            const localAddress = address.user
                .replace(/^SRS\d+=/i, value => value.toUpperCase())
                .replace(/([-=+][0-9a-f]{4})(=[A-Z2-7]{2}=)/i, (str, sig, ts) => sig + ts.toUpperCase());

            return localAddress + '@' + punycode.toUnicode(address.host.toLowerCase().trim());
        }

        return tools.normalizeAddress(address.address());
    }

    async increment_forward_counters(connection) {
        const txn = connection.transaction;

        if (!txn?.notes?.targets?.forwardCounters) {
            return false;
        }

        const { forwardCounters } = txn.notes.targets;
        await Promise.all(
            Array.from(forwardCounters.entries()).map(async ([key, { increment, limit }]) => {
                try {
                    const ttlres = await this.ttlcounterAsync('wdf:' + key, increment, limit, false);
                    connection.loginfo(this, `Forward counter updated for ${key} (${increment}/${limit}): ${JSON.stringify(ttlres)}`);
                } catch (err) {
                    connection.logerror(this, err.message);
                }
            })
        );
    }

    async handle_forwarding_address(connection, address, addressData) {
        const txn = connection.transaction;

        if (!txn?.notes?.targets?.forwardCounters) {
            connection.logerror(this, 'Empty transaction, can not forward');
            return false;
        }

        const { forwards, autoreplies, forwardCounters } = txn.notes.targets;
        const forwardLimit = addressData.forwards || txn.notes.settings['const:max:forwards'];

        let limitResult;
        try {
            limitResult = await this.ttlcounterAsync(
                'wdf:' + addressData._id.toString(),
                0,
                forwardLimit,
                false
            );
        } catch (err) {
            err.resolution = {
                _stack: err.stack,
                _forward: 'yes',
                _rate_limit: 'yes',
                _selector: 'user',
                _failure: 'yes',
                _failure_msg: 'rate limit check failed',
                _err_code: err.code
            };
            err.code = err.code || 'RateLimit';
            throw err;
        }

        if (!limitResult.success) {
            connection.lognotice(
                this,
                'RATELIMITED target=' +
                addressData.address +
                ' key=' +
                addressData._id +
                ' limit=' +
                addressData.forwards +
                ' value=' +
                limitResult.value +
                ' ttl=' +
                limitResult.ttl
            );

            const error = new Error('Rate limit hit');
            error.resolution = {
                _forward: 'yes',
                _rate_limit: 'yes',
                _selector: 'user',
                _error: 'too many attempts'
            };
            txn.notes.rejectCode = 'RATE_LIMIT';

            error.responseAction = DENY;
            error.responseMessage = DSN.rcpt_too_fast();
            throw error;
        }

        if (addressData.forwardedDisabled) {
            const error = new Error('Mailbox disabled');

            error.resolution = {
                _address: addressData._id.toString(),
                _error: 'disabled forwarded address',
                _disabled_forwarded: 'yes'
            };
            txn.notes.rejectCode = 'MBOX_DISABLED';

            error.responseAction = DENY;
            error.responseMessage = DSN.mbox_disabled();
            throw error;
        }

        connection.loginfo(
            this,
            'FORWARDING rcpt=' +
            address +
            ' address=' +
            addressData.address +
            '[' +
            addressData._id +
            ']' +
            ' target=' +
            addressData.targets.map(target => ((target && target.value) || target).toString().replace(/\?.*$/, '')).join(', ')
        );

        if (addressData.autoreply) {
            autoreplies.set(addressData.addrview, addressData);
        }

        const forwardTargets = [];
        for (const targetData of addressData.targets) {
            if (targetData.type === 'relay') {
                targetData.recipient = addressData.address || address;
                forwards.set(`${targetData.recipient}:${targetData.value}`, targetData);
                forwardTargets.push(targetData.recipient + ':' + (targetData.value || '').toString().replace(/\?.*$/, ''));
                continue;
            }

            if (targetData.type !== 'mail') {
                forwardTargets.push(address + ':' + targetData.value);
                targetData.recipient = address;
            } else {
                forwardTargets.push(targetData.value);
            }

            forwards.set(targetData.value, targetData);
        }

        forwardCounters.set(addressData._id.toString(), {
            increment: forwardTargets.length,
            limit: forwardLimit
        });

        txn.notes.rejectCode = false;
        return {
            resolution: {
                _forward: 'yes',
                _rcpt_accepted: 'yes',
                _forward_to: forwardTargets.join('\n') || 'empty_list',
                _address: addressData.address
            }
        };
    }

    async init_wildduck_transaction(connection) {
        const txn = connection.transaction;

        if (!txn || txn.notes.id) {
            return;
        }

        txn.notes.id = new ObjectId();
        txn.notes.rateKeys = [];
        txn.notes.targets = {
            users: new Map(),
            forwards: new Map(),
            recipients: new Set(),
            autoreplies: new Map(),
            forwardCounters: new Map()
        };

        txn.notes.transmissionType = connection.session.transmissionType;

        try {
            txn.notes.settings = await this.db.settingsHandler.getMulti([
                'const:max:storage',
                'const:max:recipients',
                'const:max:forwards',
                'const:domaincache:enabled'
            ]);
        } catch (err) {
            connection.logerror(this, err.message);
        }
    }

    hook_mail(next, connection, params) {
        this.init_wildduck_transaction(connection).then(() => {
            authHookMail(this, connection, params)
                .then(() => {
                    next();
                })
                .catch(err => next(err.smtpAction || DENYSOFT, err.message));
        });
    }

    hook_rcpt(next, connection, params) {
        const txn = connection.transaction;

        let tryCount = 0;
        let tryTimer = false;
        let returned = false;
        let waitTimeout = false;

        const runHandler = () => {
            clearTimeout(tryTimer);
            this.init_wildduck_transaction(connection).then(() => {
                this.real_rcpt_handler(
                    (...args) => {
                        clearTimeout(waitTimeout);
                        if (returned) {
                            return;
                        }
                        returned = true;
                        const err = args && args[0];
                        if (err && /Error$/.test(err.name)) {
                            connection.logerror(this, err.message);
                            txn.notes.rejectCode = 'ERRC01';
                            return next(DENYSOFT, 'Failed to process recipient, try again [ERRC01]');
                        }
                        next(...args);
                    },
                    connection,
                    params
                );
            });
        };

        const runCheck = () => {
            if (returned) {
                return;
            }
            if (!this.db) {
                if (tryCount++ < 5) {
                    tryTimer = setTimeout(runCheck, tryCount * 150);
                    return;
                }
                clearTimeout(waitTimeout);
                returned = true;
                txn.notes.rejectCode = 'ERRC02';
                return next(DENYSOFT, 'Failed to process recipient, try again [ERRC02]');
            }
            runHandler();
        };

        waitTimeout = setTimeout(() => {
            clearTimeout(waitTimeout);
            if (returned) {
                return;
            }
            returned = true;
            txn.notes.rejectCode = 'ERRC03';
            return next(DENYSOFT, 'Failed to process recipient, try again [ERRC03]');
        }, 8 * 1000);

        runCheck();
    }

    real_rcpt_handler(next, connection, params) {
        const txn = connection.transaction;
        const remoteIp = connection.remote.ip;

        const { recipients, forwards, users } = txn.notes.targets;

        const rcpt = params[0];
        if (/\*/.test(rcpt.user)) {
            txn.notes.rejectCode = 'NO_SUCH_USER';
            return next(DENY, DSN.no_such_user());
        }

        const address = this.normalize_address(rcpt);

        recipients.add(address);

        let resolution = false;
        const hookDone = (...args) => {
            if (resolution) {
                const message = {
                    short_message: '[RCPT TO:' + rcpt.address() + '] ' + txn.uuid,
                    _mail_action: 'rcpt_to',
                    _from: txn.notes.sender,
                    _to: rcpt.address(),
                    _queue_id: txn.uuid,
                    _ip: remoteIp,
                    _proto: txn.notes.transmissionType
                };

                Object.keys(resolution).forEach(key => {
                    if (resolution[key]) {
                        message[key] = resolution[key];
                    }
                });

                this.loggelf(message);
            }
            next(...args);
        };

        connection.logdebug(this, 'Checking validity of ' + address);

        if (/^SRS\d+=/.test(address)) {
            let reversed = false;
            try {
                reversed = this.srsRewriter.reverse(address.substr(0, address.indexOf('@')));
                const toDomain = punycode.toASCII((reversed[1] || '').toString().toLowerCase().trim());

                if (!toDomain) {
                    connection.logerror(this, 'SRS FAILED rcpt=' + address + ' error=Missing domain');
                    resolution = {
                        _srs: 'yes',
                        _error: 'missing domain'
                    };
                    txn.notes.rejectCode = 'NO_SUCH_USER';
                    return hookDone(DENY, DSN.no_such_user());
                }

                reversed = reversed.join('@');
            } catch (err) {
                connection.logerror(this, 'SRS FAILED rcpt=' + address + ' error=' + err.message);
                resolution = {
                    _stack: err.stack,
                    _srs: 'yes',
                    _failure: 'yes',
                    _failure_msg: 'srs check failed',
                    _err_code: err.code
                };
                txn.notes.rejectCode = 'NO_SUCH_USER';
                return hookDone(DENY, DSN.no_such_user());
            }

            if (reversed) {
                const key = reversed;
                const selector = 'rcpt';
                return this.checkRateLimit(connection, selector, key, false, (err, success) => {
                    if (err) {
                        resolution = {
                            _stack: err.stack,
                            _srs: 'yes',
                            _rate_limit: 'yes',
                            _selector: selector,
                            _failure: 'yes',
                            _failure_msg: 'rate limit check failed',
                            _err_code: err.code
                        };
                        err.code = err.code || 'RateLimit';
                        return hookDone(err);
                    }

                    if (!success) {
                        resolution = {
                            _srs: 'yes',
                            _rate_limit: 'yes',
                            _selector: selector,
                            _error: 'too many attempts'
                        };
                        txn.notes.rejectCode = 'RATE_LIMIT';
                        return hookDone(DENYSOFT, DSN.rcpt_too_fast());
                    }

                    txn.notes.rateKeys.push({ selector, key });

                    connection.loginfo(this, `SRS USING rcpt=${address} target=${reversed}`);

                    forwards.set(reversed, { type: 'mail', value: reversed, recipient: rcpt.address() });

                    resolution = {
                        _srs: 'yes',
                        _rcpt_accepted: 'yes',
                        _forward_to: reversed
                    };

                    txn.notes.rejectCode = false;
                    return hookDone(OK);
                });
            }
        }

        const checkIpRateLimit = (userData, done) => {
            if (!remoteIp) {
                return done();
            }

            const key = remoteIp + ':' + userData._id.toString();
            const selector = 'rcptIp';
            this.checkRateLimit(connection, selector, key, false, (err, success) => {
                if (err) {
                    resolution = {
                        _stack: err.stack,
                        _rate_limit: 'yes',
                        _selector: selector,
                        _user: userData._id.toString(),
                        _default_address: rcpt.address() !== userData.address ? userData.address : '',
                        _failure_msg: 'rate limit check failed',
                        _failure: 'yes',
                        _err_code: err.code
                    };
                    err.code = err.code || 'RateLimit';
                    return hookDone(err);
                }

                if (!success) {
                    resolution = {
                        _rate_limit: 'yes',
                        _selector: selector,
                        _error: 'too many attempts',
                        _user: userData._id.toString(),
                        _default_address: rcpt.address() !== userData.address ? userData.address : ''
                    };
                    txn.notes.rejectCode = 'RATE_LIMIT';
                    return hookDone(DENYSOFT, DSN.rcpt_too_fast());
                }

                txn.notes.rateKeys.push({ selector, key });
                return done();
            });
        };

        const resolveAddress = () => {
            this.db.userHandler.resolveAddress(
                address,
                {
                    wildcard: true,
                    projection: {
                        name: true,
                        address: true,
                        addrview: true,
                        forwards: true,
                        autoreply: true,
                        targets: true,
                        forwardedDisabled: true
                    }
                },
                (err, addressData) => {
                    if (err) {
                        resolution = {
                            full_message: err.stack,
                            _api: 'resolveAddress',
                            _db_query: 'address:' + address,
                            _failure_msg: 'failed to resolve an address',
                            _failure: 'yes',
                            _err_code: err.code
                        };
                        err.code = err.code || 'ResolveAddress';
                        return hookDone(err);
                    }

                    if (addressData && addressData.address && addressData.address.includes('*')) {
                        const originalRcptHeaderName = this.cfg?.originalRcptHeader || 'X-Original-Rcpt';
                        txn.add_header(originalRcptHeaderName, address);
                    }

                    if (addressData && addressData.targets) {
                        return this
                            .handle_forwarding_address(connection, address, addressData)
                            .then(result => {
                                if (result && result.resolution) {
                                    resolution = result.resolution;
                                }
                                hookDone(OK);
                            })
                            .catch(err => {
                                if (err.resolution) {
                                    resolution = err.resolution;
                                }
                                if (err.responseAction) {
                                    return hookDone(err.responseAction, err.responseMessage || err);
                                } else {
                                    return hookDone(err);
                                }
                            });
                    }

                    if (!addressData || !addressData.user) {
                        connection.logdebug(this, 'No such user ' + address);
                        resolution = {
                            _error: 'no such user',
                            _unknown_user: 'yes'
                        };
                        txn.notes.rejectCode = 'NO_SUCH_USER';
                        return hookDone(DENY, DSN.no_such_user());
                    }

                    this.db.userHandler.get(
                        addressData.user,
                        {
                            name: true,
                            address: true,
                            forwards: true,
                            receivedMax: true,
                            targets: true,
                            autoreply: true,
                            encryptMessages: true,
                            encryptForwarded: true,
                            pubKey: true,
                            spamLevel: true,
                            storageUsed: true,
                            quota: true,
                            tagsview: true,
                            mtaRelay: true
                        },
                        (err, userData) => {
                            if (err) {
                                resolution = {
                                    full_message: err.stack,
                                    _api: 'getUser',
                                    _db_query: 'user:' + addressData.user,
                                    _error: 'failed to fetch user',
                                    _failure: 'yes',
                                    _err_code: err.code
                                };
                                err.code = err.code || 'GetUserData';
                                return hookDone(err);
                            }

                            if (!userData) {
                                resolution = {
                                    _error: 'no such user',
                                    _unknown_user: 'yes'
                                };
                                txn.notes.rejectCode = 'NO_SUCH_USER';
                                return hookDone(DENY, DSN.no_such_user());
                            }

                            if (userData.disabled) {
                                resolution = {
                                    _user: userData._id.toString(),
                                    _error: 'disabled user',
                                    _disabled_user: 'yes'
                                };
                                txn.notes.rejectCode = 'MBOX_DISABLED';
                                return hookDone(DENY, DSN.mbox_disabled());
                            }

                            const quota = userData.quota || txn.notes.settings['const:max:storage'];
                            if (userData.storageUsed && quota <= userData.storageUsed) {
                                resolution = {
                                    _user: userData._id.toString(),
                                    _error: 'user over quota',
                                    _over_quota: 'yes',
                                    _max_quota: quota,
                                    _quota_source: userData.quota ? 'user' : 'config',
                                    _storage_used: userData.storageUsed,
                                    _default_address: rcpt.address() !== userData.address ? userData.address : ''
                                };
                                txn.notes.rejectCode = 'MBOX_FULL';
                                return hookDone(DENY, DSN.mbox_full_554());
                            }

                            checkIpRateLimit(userData, () => {
                                const key = userData._id.toString();
                                const selector = 'rcpt';
                                this.checkRateLimit(connection, selector, key, userData.receivedMax, (err, success) => {
                                    if (err) {
                                        resolution = {
                                            _stack: err.stack,
                                            _rate_limit: 'yes',
                                            _selector: selector,
                                            _user: userData._id.toString(),
                                            _default_address: rcpt.address() !== userData.address ? userData.address : '',
                                            _failure_msg: 'rate limit check failed',
                                            _failure: 'yes',
                                            _err_code: err.code
                                        };
                                        err.code = err.code || 'RateLimit';
                                        return hookDone(err);
                                    }

                                    if (!success) {
                                        resolution = {
                                            _rate_limit: 'yes',
                                            _selector: selector,
                                            _error: 'too many attempts',
                                            _user: userData._id.toString(),
                                            _default_address: rcpt.address() !== userData.address ? userData.address : ''
                                        };
                                        txn.notes.rejectCode = 'RATE_LIMIT';
                                        return hookDone(DENYSOFT, DSN.rcpt_too_fast());
                                    }

                                    connection.loginfo(this, 'RESOLVED rcpt=' + rcpt.address() + ' user=' + userData.address + '[' + userData._id + ']');

                                    txn.notes.rateKeys.push({ selector, key, limit: userData.receivedMax });

                                    users.set(userData._id.toString(), {
                                        userData,
                                        recipient: rcpt.address()
                                    });

                                    resolution = {
                                        _user: userData._id.toString(),
                                        _rcpt_accepted: 'yes',
                                        _default_address: rcpt.address() !== userData.address ? userData.address : ''
                                    };
                                    txn.notes.rejectCode = false;
                                    hookDone(OK);
                                });
                            });
                        }
                    );
                }
            );
        };

        if (txn.notes.settings['const:domaincache:enabled']) {
            const addressDomain = address.split('@')[1];

            this.db.users.collection('domaincache').findOne({ domain: addressDomain }, { projection: { _id: 1 } }, (err, data) => {
                if (err) {
                    resolution = {
                        _stack: err.stack,
                        _api: 'getDomaincache',
                        _db_query: 'domain:' + addressDomain,
                        _failure_msg: 'failed to resolve domain in domain cache',
                        _failure: 'yes',
                        _err_code: err.code
                    };
                    err.code = err.code || 'GetDomainCache';
                    return hookDone(err);
                }

                if (!data) {
                    resolution = {
                        _api: 'getDomaincache',
                        _db_query: 'domain:' + addressDomain,
                        _error: 'domain not found in domain cache',
                        _failure: 'yes'
                    };

                    return hookDone(DENY, DSN.addr_bad_dest_mbox());
                }

                return resolveAddress();
            });
        } else {
            resolveAddress();
        }
    }

    hook_queue(next, connection) {
        const txn = connection.transaction;
        const queueId = txn.uuid;
        const remoteIp = connection.remote.ip;
        const { forwards, autoreplies, users } = txn.notes.targets;
        const transhost = connection.hello.host;

        const blacklisted = this.checkRspamdBlacklist(txn);
        if (blacklisted) {
            txn.notes.rejectCode = blacklisted.key;
            return next(DENY, this.dsnSpamResponse(txn, blacklisted.key).reply);
        }

        const softlisted = this.checkRspamdSoftlist(txn);
        if (softlisted) {
            txn.notes.rejectCode = softlisted.key;
            return next(DENYSOFT, this.dsnSpamResponse(txn, softlisted.key).reply);
        }

        const verificationResults = {
            tls: false,
            spf: false,
            dmarc: false,
            dkim: false,
            arc: false,
            bimi: false
        };

        const tlsResults = connection.results.get('tls');
        if (tlsResults && tlsResults.enabled) {
            verificationResults.tls = tlsResults.cipher;
        }

        const envelopeFrom = txn.notes.sender;
        const headerFrom = this.getHeaderFrom(txn);

        if (txn.notes.spfResult?.status?.result === 'pass' && txn.notes.spfResult?.domain) {
            verificationResults.spf = txn.notes.spfResult?.domain;
        }

        if (txn.notes.dmarcResult?.status?.result === 'pass' && txn.notes.dmarcResult?.domain) {
            verificationResults.dmarc = {
                domain: txn.notes.dmarcResult?.domain,
                policy: txn.notes.dmarcResult?.policy
            };
        }

        const dkimResults = (txn.notes.dkimResult?.results || []).sort((a, b) => {
            if (a.status === 'pass' && b.status !== 'pass') {
                return -1;
            }
            if (a.status !== 'pass' && b.status === 'pass') {
                return 1;
            }
            if (a.status?.aligned && !b.status?.aligned) {
                return -1;
            }
            if (!a.status?.aligned && b.status?.aligned) {
                return 1;
            }
            if (a.status?.aligned && b.status?.aligned) {
                return a.status?.aligned.localeCompare(b.status?.aligned);
            }
            return a.signingDomain.localeCompare(b.signingDomain);
        });

        if (dkimResults[0]?.status?.result === 'pass') {
            verificationResults.dkim = dkimResults[0]?.signingDomain;
        }

        if (txn.notes.arcResult?.status?.result === 'pass' && txn.notes.arcResult?.signature?.signingDomain) {
            verificationResults.arc = txn.notes.arcResult?.signature?.signingDomain;
        }

        if (txn.notes.bimiResult?.status?.result === 'pass' && txn.notes?.bimi) {
            verificationResults.bimi = txn.notes.bimi;
        }

        const messageId = (txn.header.get('Message-Id') || '').toString();
        let subject = (txn.header.get('Subject') || '').toString();

        const sendLogEntry = resolution => {
            if (resolution) {
                const rspamd = txn.results.get('rspamd');

                try {
                    subject = libmime.decodeWords(subject).trim();
                } catch {
                    // ignore
                }

                const message = {
                    short_message: '[PROCESS] ' + queueId,
                    _mail_action: 'process',
                    _queue_id: queueId,
                    _ip: remoteIp,
                    _message_id: messageId.trim(),
                    _spam_score: rspamd ? rspamd.score : '',
                    _spam_action: rspamd ? rspamd.action : '',
                    _from: envelopeFrom,
                    _subject: subject
                };

                if (headerFrom) {
                    message._header_from = headerFrom.address;
                    message._header_from_name = headerFrom.provided && headerFrom.provided.name;
                    message._header_from_value = txn.header.get_all('From').join('; ');
                }

                Object.keys(resolution).forEach(key => {
                    if (resolution[key]) {
                        message[key] = resolution[key];
                    }
                });

                message._spam_tests = this.rspamdSymbols(txn)
                    .map(symbol => `${symbol.key}=${symbol.score}`)
                    .join(', ');

                this.loggelf(message);
            }
        };

        const finalChunks = txn.getMessageChunks();
        const finalChunkLength = txn.getMessageSize();
        const finalBuffer = finalChunks[0];
        const referencedUsers = this.getReferencedUsers(txn);
        const allowAutoreply = new Set();

        referencedUsers.forEach(user => {
            allowAutoreply.add(user.userData._id.toString());
        });

        const forwardMessage = async () => {
            if (!forwards.size) {
                return true;
            }

            const rspamd = txn.results.get('rspamd');
            if (rspamd && rspamd.score && this.rspamd.forwardSkip && rspamd.score >= this.rspamd.forwardSkip) {
                connection.loginfo(this, 'FORWARDSKIP score=' + JSON.stringify(rspamd.score) + ' required=' + this.rspamd.forwardSkip);

                const message = {
                    short_message: '[Skip forward] ' + queueId,
                    _mail_action: 'forward',
                    _forward_skipped: 'yes',
                    _spam_score: rspamd ? rspamd.score : '',
                    _spam_action: rspamd ? rspamd.action : '',
                    _spam_allowed: this.rspamd.forwardSkip
                };

                message._spam_tests = this.rspamdSymbols(txn)
                    .map(symbol => `${symbol.key}=${symbol.score}`)
                    .join(', ');

                sendLogEntry(message);
                return true;
            }

            const targets =
                (forwards.size &&
                    Array.from(forwards).map(row => ({
                        type: row[1].type,
                        value: row[1].value,
                        recipient: row[1].recipient
                    }))) ||
                false;

            let user;

            for (const availableUser of users.values()) {
                if (availableUser.userData?.address === txn.notes.sender) {
                    user = availableUser.userData;
                }
            }

            const mail = {
                parentId: txn.notes.id,
                reason: 'forward',
                from: txn.notes.sender,
                to: [],
                targets,
                interface: 'forwarder'
            };

            if (user) {
                mail.mtaRelay = user.mtaRelay || false;
            }

            await new Promise((resolve, reject) => {
                const message = this.maildrop.push(mail, async (err, envelope) => {
                    if (err || !envelope) {
                        if (err) {
                            err.code = err.code || 'ERRCOMPOSE';
                            sendLogEntry({
                                short_message: '[Failed forward] ' + queueId,
                                _stack: err.stack,
                                _failure_msg: 'failed to store message',
                                _mail_action: 'forward',
                                _failure: 'yes',
                                _err_code: err.code
                            });
                        }
                        return reject(err || new Error('Failed to queue forward'));
                    }

                    sendLogEntry({
                        short_message: '[Queued forward] ' + queueId,
                        _mail_action: 'forward',
                        _target_queue_id: envelope.id,
                        _target_address: targets.map(target => ((target && target.value) || target).toString().replace(/\?.*$/, '')).join('\n')
                    });

                    this.loggelf({
                        _queue_id: envelope.id,
                        short_message: '[QUEUED] ' + envelope.id,
                        _parent_queue_id: queueId,
                        _from: txn.notes.sender,
                        _to: targets.map(target => ((target && target.value) || target).toString().replace(/\?.*$/, '')).join('\n'),
                        _queued: 'yes',
                        _forwarded: 'yes',
                        _interface: 'mx'
                    });

                    connection.loginfo(this, 'QUEUED FORWARD queue-id=' + envelope.id);

                    try {
                        if (txn.notes.targets && txn.notes.targets.forwardCounters) {
                            await this.increment_forward_counters(connection);
                        }
                    } catch (incrementErr) {
                        connection.logerror(this, incrementErr.message);
                    }

                    resolve(envelope.id);
                });

                if (!message) {
                    return reject(new Error('Maildrop rejected forward message'));
                }

                message.once('error', err => {
                    connection.logerror(this, 'QUEUEERROR Failed to retrieve message. error=' + err.message);
                    sendLogEntry({
                        full_message: err.stack,
                        _error: 'failed to retrieve message from input',
                        _failure: 'yes',
                        _err_code: err.code
                    });
                    txn.notes.rejectCode = 'ERRQ04';
                    reject(new Error('Failed to queue message [ERRQ04]'));
                });

                message.end(finalBuffer);
            });
        };

        const sendAutoreplies = async () => {
            if (!autoreplies.size) {
                return;
            }

            const curtime = new Date();
            const autoreplyEntries = Array.from(autoreplies);

            await runSequentially(autoreplyEntries, async target => {
                const addressData = target[1];

                const autoreplyData = addressData.autoreply;
                autoreplyData._id = autoreplyData._id || addressData._id;

                if (!autoreplyData || !autoreplyData.status) {
                    return;
                }

                if (autoreplyData.start && autoreplyData.start > curtime) {
                    return;
                }

                if (autoreplyData.end && autoreplyData.end < curtime) {
                    return;
                }

                try {
                    const result = await autoreply(
                        {
                            db: this.db,
                            queueId,
                            maildrop: this.maildrop,
                            sender: txn.notes.sender,
                            recipient: addressData.address,
                            chunks: finalChunks,
                            chunklen: finalChunkLength,
                            messageHandler: this.db.messageHandler
                        },
                        autoreplyData
                    );

                    if (!result) {
                        return;
                    }

                    sendLogEntry({
                        short_message: '[Queued autoreply] ' + queueId,
                        _mail_action: 'autoreply',
                        _target_queue_id: result.id,
                        _target_address: addressData.address
                    });

                    this.loggelf({
                        _queue_id: result.id,
                        short_message: '[QUEUED] ' + result.id,
                        _parent_queue_id: queueId,
                        _from: addressData.address,
                        _to: addressData.address,
                        _queued: 'yes',
                        _autoreply: 'yes',
                        _interface: 'mx'
                    });

                    connection.loginfo(this, 'QUEUED AUTOREPLY target=' + txn.notes.sender + ' queue-id=' + result.id);
                } catch (err) {
                    connection.lognotice(this, 'AUTOREPLY ERROR target=' + txn.notes.sender + ' error=' + err.message);
                    sendLogEntry({
                        short_message: '[Autoreply error] ' + queueId,
                        _mail_action: 'autoreply',
                        _target_address: addressData.address,
                        _parent_queue_id: queueId,
                        _from: addressData.address,
                        _to: addressData.address,
                        _failure: 'yes',
                        _error: err.message,
                        _err_code: err.code
                    });
                }
            });
        };

        const updateRateLimits = async () => {
            const rateKeys = txn.notes.rateKeys || [];
            await Promise.all(
                rateKeys.map(rateKey => {
                    connection.logdebug(this, 'Rate key. key=' + JSON.stringify(rateKey));
                    return this.updateRateLimit(this, connection, rateKey.selector || 'rcpt', rateKey.key, rateKey.limit);
                })
            );
            connection.logdebug(this, 'Rate keys processed');
        };

        const storeMessages = async () => {
            let prepared = false;
            const userList = Array.from(users).map(entry => entry[1]);
            const zilter = txn.results.get('zilter');
            let result = false;

            await runSequentially(userList, async rcptData => {
                if (result) {
                    return;
                }

                const rspamd = txn.results.get('rspamd');
                const recipient = rcptData.recipient;
                const userData = rcptData.userData;
                const zilterOverrides = zilter?.['rcpt-overrides']?.[recipient];

                connection.logdebug(this, 'Filtering message for ' + recipient);

                sendLogEntry({
                    short_message: '[MX FILTER-HANDLER] Started storing message',
                    _user: userData._id.toString(),
                    _to: recipient
                });

                try {
                    const start = Date.now();
                    const { response, prepared: preparedResponse } = await this.filterHandler.storeMessage(userData, {
                        mimeTree: prepared && prepared.mimeTree,
                        maildata: prepared && prepared.maildata,
                        user: userData,
                        mailbox: rcptData.mailbox,
                        sender: txn.notes.sender,
                        recipient,
                        chunks: finalChunks,
                        chunklen: finalChunkLength,
                        disableAutoreply: !allowAutoreply.has(userData._id.toString()),
                        verificationResults,
                        meta: {
                            transactionId: queueId,
                            source: 'MX',
                            from: txn.notes.sender,
                            to: [recipient],
                            origin: remoteIp,
                            transhost,
                            transtype: txn.notes.transmissionType,
                            spamScore: rspamd ? rspamd.score : false,
                            spamAction: rspamd ? rspamd.action : false,
                            overrides: zilterOverrides || false,
                            time: new Date()
                        }
                    });

                    sendLogEntry({
                        short_message: '[MX FILTER-HANDLER] Finished storing message',
                        _user: userData._id.toString(),
                        _to: recipient,
                        _elapsed: Date.now() - start
                    });

                    if (!prepared && preparedResponse) {
                        prepared = preparedResponse;
                    }

                    if (!response) {
                        throw new Error('Missing response');
                    }

                    let targetMailbox;
                    let targetId;
                    let isSpam = false;
                    const overrideFlags = Array.isArray(zilterOverrides?.flags) ? zilterOverrides.flags : [];
                    const overrideIsSpam = overrideFlags.length
                        ? overrideFlags.some(flag => (flag || '').toString().toLowerCase() !== 'ham')
                        : undefined;
                    const filterMessages = [];
                    let matchingFilters;

                    if (response.attachments && response.attachments.length) {
                        response.attachments.forEach(attachment => {
                            sendLogEntry({
                                short_message: '[ATT] ' + attachment.id,
                                _user: userData._id.toString(),
                                _to: recipient,
                                _mail_action: 'attachment',
                                _attachment_id: attachment.id,
                                _encoded_sha256: attachment.encodedSha256,
                                _filename: attachment.filename,
                                _content_type: attachment.contentType,
                                _attachment_disposition: attachment.disposition,
                                _attachment_size: attachment.size,
                                _attachment_encoding: attachment.transferEncoding,
                                _attachment_count: response.attachments.length,
                                _attachment_sha256: attachment.fileContentHash
                            });
                        });
                    }

                    if (response.filterResults && response.filterResults.length) {
                        response.filterResults.forEach(entry => {
                            if (entry.forward) {
                                sendLogEntry({
                                    short_message: '[Queued forward] ' + queueId,
                                    _user: userData._id.toString(),
                                    _to: recipient,
                                    _mail_action: 'forward',
                                    _target_queue_id: entry['forward-queue-id'],
                                    _target_address: entry.forward
                                });

                                this.loggelf({
                                    short_message: '[QUEUED] ' + entry['forward-queue-id'],
                                    _queue_id: entry['forward-queue-id'],
                                    _parent_queue_id: queueId,
                                    _from: recipient,
                                    _to: entry.forward,
                                    _queued: 'yes',
                                    _forwarded: 'yes',
                                    _interface: 'mx'
                                });
                                return;
                            }

                            if (entry.autoreply) {
                                sendLogEntry({
                                    short_message: '[Queued autoreply] ' + queueId,
                                    _mail_action: 'autoreply',
                                    _user: userData._id.toString(),
                                    _to: recipient,
                                    _target_queue_id: entry['autoreply-queue-id'],
                                    _target_address: entry.autoreply
                                });

                                this.loggelf({
                                    short_message: '[QUEUED] ' + entry['autoreply-queue-id'],
                                    _queue_id: entry['autoreply-queue-id'],
                                    _parent_queue_id: queueId,
                                    _from: recipient,
                                    _to: entry.autoreply,
                                    _queued: 'yes',
                                    _autoreply: 'yes',
                                    _interface: 'mx'
                                });
                                return;
                            }

                            if ('spam' in entry || 'originalSpam' in entry) {
                                isSpam = 'originalSpam' in entry ? !!entry.originalSpam : !!entry.spam;
                                if (entry.spam) {
                                    filterMessages.push('Spam');
                                }
                                return;
                            }

                            if (entry.mailbox && entry.id) {
                                targetMailbox = entry.mailbox && { mailbox: entry.mailbox, path: entry.path, uid: entry.uid };
                                targetId = entry.id;
                                return;
                            }

                            if (entry.matchingFilters && entry.matchingFilters.length) {
                                matchingFilters = entry.matchingFilters;
                                return;
                            }

                            Object.keys(entry).forEach(key => {
                                if (!entry[key]) {
                                    return;
                                }
                                if (typeof entry[key] === 'boolean') {
                                    filterMessages.push(key);
                                } else {
                                    filterMessages.push(key + '=' + (entry[key] || '').toString());
                                }
                            });
                        });

                        if (filterMessages.length) {
                            connection.loginfo(this, 'FILTER ACTIONS ' + filterMessages.join(','));
                        }
                    }

                    if (response.error) {
                        txn.notes.rejectCode = response.error.code;

                        if (response.error.code === 'DroppedByPolicy') {
                            sendLogEntry({
                                _stack: response.error.message,
                                _user: userData._id.toString(),
                                _to: recipient,
                                _filter: filterMessages.length ? filterMessages.join('\n') : '',
                                _filter_is_spam: isSpam ? 'yes' : 'no',
                                _filters_matching: matchingFilters ? matchingFilters.join('\n') : '',
                                _override_is_spam: overrideIsSpam === undefined ? undefined : overrideIsSpam ? 'yes' : 'no',
                                _no_store: 'yes',
                                _failure_msg: 'message dropped',
                                _dropped: 'yes',
                                _err_code: response.error.code
                            });

                            connection.loginfo(
                                this,
                                'DROPPED rcpt=' + recipient + ' user=' + userData.address + '[' + userData._id + '] error=' + response.error.message
                            );
                        } else {
                            sendLogEntry({
                                full_message: response.error.stack,
                                _user: userData._id.toString(),
                                _to: recipient,
                                _filter: filterMessages.length ? filterMessages.join('\n') : '',
                                _filter_is_spam: isSpam ? 'yes' : 'no',
                                _filters_matching: matchingFilters ? matchingFilters.join('\n') : '',
                                _override_is_spam: overrideIsSpam === undefined ? undefined : overrideIsSpam ? 'yes' : 'no',
                                _no_store: 'yes',
                                _error: 'failed to store message',
                                _failure: 'yes',
                                _err_code: response.error.code
                            });

                            connection.loginfo(
                                this,
                                'DEFERRED rcpt=' + recipient + ' user=' + userData.address + '[' + userData._id + '] error=' + response.error.message
                            );

                            result = [DENYSOFT, response.error.message];
                            return;
                        }
                    } else {
                        sendLogEntry({
                            _user: userData._id.toString(),
                            _to: recipient,
                            _stored: 'yes',
                            _store_result: response.response,
                            _filter: filterMessages.length ? filterMessages.join('\n') : '',
                            _filter_is_spam: isSpam ? 'yes' : 'no',
                            _filters_matching: matchingFilters ? matchingFilters.join('\n') : '',
                            _override_is_spam: overrideIsSpam === undefined ? undefined : overrideIsSpam ? 'yes' : 'no',
                            _stored_mailbox: targetMailbox && targetMailbox.mailbox,
                            _stored_path: targetMailbox && targetMailbox.path,
                            _stored_uid: targetMailbox && targetMailbox.uid,
                            _stored_id: targetId,
                            _stored_size: response.size
                        });

                        connection.loginfo(this, 'STORED rcpt=' + recipient + ' user=' + userData.address + '[' + userData._id + '] result=' + response.response);
                    }
                } catch (err) {
                    sendLogEntry({
                        full_message: err.stack,
                        _user: userData._id.toString(),
                        _address: recipient,
                        _no_store: 'yes',
                        _error: 'failed to store message',
                        _failure: 'yes',
                        _err_code: err.code
                    });

                    switch (err.code) {
                        case 15:
                            connection.loginfo(this, 'REJECTED rcpt=' + recipient + ' error=' + err.message);
                            txn.notes.rejectCode = 'ERRQ07';
                            result = [DENY, 'Failed to queue message, too many nested attachments [ERRQ07]'];
                            return;
                        default:
                            connection.loginfo(this, 'DEFERRED rcpt=' + recipient + ' error=' + err.message);
                            txn.notes.rejectCode = 'ERRQ05';
                            result = [DENYSOFT, 'Failed to queue message [ERRQ05]'];
                            return;
                    }
                }
            });

            if (result) {
                return result;
            }

            await updateRateLimits();

            sendLogEntry({
                short_message: '[MX RATE-LIMITS] Updated rate limits'
            });

            return [OK, 'Message processed'];
        };

        const processQueue = async () => {
            try {
                await forwardMessage();
            } catch (err) {
                return [DENYSOFT, err.message];
            }

            try {
                await sendAutoreplies();
            } catch (err) {
                connection.logerror(this, 'AUTOREPLY error=' + err.message);
            }

            try {
                return await storeMessages();
            } catch (err) {
                sendLogEntry({
                    full_message: err.stack,
                    _no_store: 'yes',
                    _error: 'failed to store message',
                    _failure: 'yes',
                    _err_code: err.code
                });

                connection.loginfo(this, 'DEFERRED error=' + err.message);
                txn.notes.rejectCode = 'ERRQ06';
                return [DENYSOFT, 'Failed to queue message [ERRQ06]'];
            }
        };

        processQueue()
            .then(result => {
                next(...result);
            })
            .catch(err => {
                next(DENYSOFT, err.message || 'Failed to queue message');
            });
    }

    checkRateLimit(connection, selector, key, limit, next) {
        limit = Number(limit) || this.cfg.limits[selector];
        if (!limit) {
            return next(null, true);
        }

        const windowSize = this.cfg.limits[selector + 'WindowSize'] || this.cfg.limits.windowSize || 1 * 3600;

        this.ttlcounter('rl:' + selector + ':' + key, 0, limit, windowSize, (err, result) => {
            if (err) {
                connection.logerror(this, 'RATELIMITERR error=' + err.message);
                return next(err);
            }

            if (!result.success) {
                connection.lognotice(
                    this,
                    'RATELIMITED key=' + key + ' selector=' + selector + ' limit=' + limit + ' value=' + result.value + ' ttl=' + result.ttl
                );
            }

            next(null, result.success);
        });
    }

    updateRateLimit(plugin, connection, selector, key, limit) {
        limit = Number(limit) || plugin.cfg.limits[selector];
        if (!limit) {
            return Promise.resolve(true);
        }

        const windowSize = plugin.cfg.limits[selector + 'WindowSize'] || plugin.cfg.limits.windowSize || 1 * 3600;

        return new Promise((resolve, reject) => {
            plugin.ttlcounter('rl:' + selector + ':' + key, 1, limit, windowSize, (err, result) => {
                if (err) {
                    connection.logerror(plugin, 'RATELIMITERR error=' + err.message);
                    return reject(err);
                }

                connection.logdebug(
                    plugin,
                    'Rate limit key=' + key + ' selector=' + selector + ' limit=' + limit + ' value=' + result.value + ' ttl=' + result.ttl
                );

                resolve(result.success);
            });
        });
    }

    getHeaderFrom(txn) {
        const fromAddresses = new Map();
        [].concat(txn.header.get_all('From') || []).forEach(entry => {
            const walk = addresses => {
                addresses.forEach(address => {
                    if (address.address) {
                        const normalized = tools.normalizeAddress(address.address, false, { removeLabel: true });
                        const uview = tools.uview(normalized);
                        try {
                            if (address.name) {
                                address.name = libmime.decodeWords(address.name).trim();
                            }
                        } catch {
                            // ignore
                        }
                        fromAddresses.set(uview, { address: normalized, provided: address });
                    } else if (address.group) {
                        walk(address.group);
                    }
                });
            };
            walk(addressparser(entry));
        });

        return Array.from(fromAddresses)
            .map(entry => entry[1])
            .shift();
    }

    getReferencedUsers(txn) {
        const { users } = txn.notes.targets;
        const referencedUsers = new Set();

        []
            .concat(txn.header.get_all('To') || [])
            .concat(txn.header.get_all('Cc') || [])
            .forEach(entry => {
                const walk = addresses => {
                    addresses.forEach(address => {
                        if (address.address) {
                            for (const user of users.values()) {
                                if (user.recipient === address.address) {
                                    referencedUsers.add(user);
                                    break;
                                }
                            }
                        } else if (address.group) {
                            walk(address.group);
                        }
                    });
                };
                walk(addressparser(entry));
            });

        return referencedUsers;
    }

    rspamdSymbols(txn) {
        const rspamd = txn.results.get('rspamd');
        const symbols = (rspamd && rspamd.symbols) || rspamd;

        const result = [];
        if (!symbols) {
            return result;
        }

        Object.keys(symbols).forEach(key => {
            let score;

            if (typeof symbols[key] === 'number') {
                score = symbols[key];
            } else if (typeof symbols[key] === 'object' && symbols[key] && typeof symbols[key].score === 'number') {
                score = symbols[key].score;
            } else {
                return;
            }
            if (score) {
                result.push({ key, value: symbols[key], score });
            }
        });

        return result;
    }

    checkRspamdBlacklist(txn) {
        const rspamd = txn.results.get('rspamd');
        const zilter = txn.results.get('zilter');
        const symbols = (rspamd && rspamd.symbols) || rspamd;

        if (!symbols) {
            return false;
        }

        const ignoreSymbols = zilter?.['ignore-symbols'];

        for (const key of this.rspamd.blacklist) {
            if (!(key in symbols)) {
                continue;
            }

            let score;
            if (typeof symbols[key] === 'number') {
                score = symbols[key];
            } else if (typeof symbols[key] === 'object' && symbols[key] && typeof symbols[key].score === 'number') {
                score = symbols[key].score;
            }

            if (score && score > 0) {
                if (Array.isArray(ignoreSymbols) && ignoreSymbols.includes(key)) {
                    this.loginfo(`Ignoring blacklisted Rspamd symbol ${key} due to zilter override`);
                    continue;
                }

                return { key, value: symbols[key] };
            }
        }

        return false;
    }

    checkRspamdSoftlist(txn) {
        const rspamd = txn.results.get('rspamd');
        const zilter = txn.results.get('zilter');
        const symbols = (rspamd && rspamd.symbols) || rspamd;

        if (!symbols) {
            return false;
        }

        const ignoreSymbols = zilter?.['ignore-symbols'];

        for (const key of this.rspamd.softlist) {
            if (!(key in symbols)) {
                continue;
            }

            let score;
            if (typeof symbols[key] === 'number') {
                score = symbols[key];
            } else if (typeof symbols[key] === 'object' && symbols[key] && typeof symbols[key].score === 'number') {
                score = symbols[key].score;
            }

            if (score && score > 0) {
                if (Array.isArray(ignoreSymbols) && ignoreSymbols.includes(key)) {
                    this.loginfo(`Ignoring softlisted Rspamd symbol ${key} due to zilter override`);
                    continue;
                }

                return { key, value: symbols[key] };
            }
        }

        return false;
    }

    dsnSpamResponse(txn, key) {
        let message = this.rspamd.responses[key] || defaultSpamRejectMessage;

        let domain;
        message = message.toString().replace(/\{host\}/gi, () => {
            if (domain) {
                return domain;
            }
            const headerFrom = this.getHeaderFrom(txn) || txn.notes.sender || '';
            domain = (headerFrom && headerFrom.address && headerFrom.address.split('@').pop()) || '-';
            return domain;
        });

        return DSN.create(550, message, 7, 1);
    }
}

module.exports.title = 'ZoneMxPluginWildduck';
module.exports.init = (plugin, done) => {
    const instance = new ZoneMxPluginWildduck(plugin);
    const promise = instance.init();

    if (typeof done === 'function') {
        promise.then(() => done()).catch(done);
    }

    return promise;
};
