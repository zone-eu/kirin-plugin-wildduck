'use strict';

const { arc } = require('mailauth/lib/arc');
const { dmarc } = require('mailauth/lib/dmarc');
const { spf: checkSpf } = require('mailauth/lib/spf');
const { dkimVerify } = require('mailauth/lib/dkim/verify');
const { bimi } = require('mailauth/lib/bimi');
const libmime = require('libmime');
const { parseReceived } = require('mailauth/lib/parse-received');
const { validateTagValueRecord } = require('mailauth/lib/tools');

async function hookMail(plugin, connection, params) {
    const txn = connection?.transaction;

    if (!txn) {
        return;
    }

    const from = params[0];
    txn.notes.sender = txn.notes.sender || (typeof from?.address === 'function' ? from.address() : from?.address || '');

    let spfResult;

    try {
        const isRemotePrivate = connection.remote.is_private;

        spfResult = await checkSpf({
            resolver: plugin.resolver,
            ip: isRemotePrivate ? undefined : connection.remote.ip,
            helo: connection.hello?.host,
            sender: txn.notes.sender,
            mta: connection.local?.host,
            maxResolveCount: plugin.cfg?.auth?.dns?.maxLookups
        });

        if (isRemotePrivate) {
            spfResult.status.result = 'softfail';
            spfResult.status.comment = 'cannot assess local addresses';
            spfResult.header = `Received-SPF: softfail (cannot assess local addresses) client-ip=${connection.remote.ip};`;
            spfResult.info = 'spf=softfail (cannot assess local addresses)';
        }

        txn.notes.spfResult = spfResult;
    } catch (err) {
        txn.notes.spfResult = { error: err };
        connection.logerror(plugin, err.message);
        return;
    }

    if (spfResult.header) {
        txn.add_leading_header('Received-SPF', spfResult.header.substring(spfResult.header.indexOf(':') + 1).trim());
    }

    if (spfResult.info) {
        connection.auth_results(spfResult.info);
    }
}

async function hookDataPost(stream, plugin, connection) {
    const txn = connection.transaction;

    const queueId = txn.uuid;

    const contentTypeHeaders = txn.header.get_all('Content-Type').map(line => libmime.parseHeaderValue(`${line}`));

    let dkimResult;
    try {
        dkimResult = await dkimVerify(stream, {
            resolver: plugin.resolver,
            sender: txn.notes.sender,
            seal: null,
            minBitLength: plugin.cfg?.auth?.minBitLength
        });
        txn.notes.dkimResult = dkimResult;

        for (const result of dkimResult?.results || []) {
            if (result.info) {
                connection.auth_results(result.info);
            }
        }
    } catch (err) {
        txn.notes.dkimResult = { error: err };
        connection.logerror(plugin, err.message);
    }

    let arcResult;
    if (dkimResult?.arc) {
        try {
            arcResult = await arc(dkimResult.arc, {
                resolver: plugin.resolver,
                minBitLength: plugin.cfg?.auth?.minBitLength
            });
            txn.notes.arcResult = arcResult;

            if (arcResult.info) {
                connection.auth_results(arcResult.info);
            }
        } catch (err) {
            txn.notes.arcResult = { error: err };
            connection.logerror(plugin, err.message);
        }
    }

    let dmarcResult;
    const spfResult = txn.notes.spfResult;
    if (dkimResult?.headerFrom) {
        const passingDomains = (dkimResult.results || [])
            .filter(r => r.status.result === 'pass')
            .map(r => ({
                id: r.id,
                domain: r.signingDomain,
                aligned: r.status.aligned,
                underSized: r.status.underSized
            }));

        try {
            dmarcResult = await dmarc({
                resolver: plugin.resolver,
                headerFrom: dkimResult.headerFrom,
                spfDomains: [].concat((spfResult?.status?.result === 'pass' && spfResult?.domain) || []),
                dkimDomains: passingDomains,
                arcResult
            });
            txn.notes.dmarcResult = dmarcResult;

            if (dmarcResult.info) {
                connection.auth_results(dmarcResult.info);
            }
        } catch (err) {
            txn.notes.dmarcResult = { error: err };
            connection.logerror(plugin, err.message);
        }
    }

    let bimiResult;
    if (dmarcResult) {
        try {
            bimiResult = await bimi({
                resolver: plugin.resolver,
                dmarc: dmarcResult,
                headers: dkimResult.headers,
                bimiWithAlignedDkim: true
            });
            txn.notes.bimiResult = bimiResult;

            txn.remove_header('bimi-location');
            txn.remove_header('bimi-indicator');

            if (bimiResult.rr) {
                const bimiLocation = validateTagValueRecord(bimiResult.rr, 'bimi').sanitizedRecord;
                if (bimiLocation) {
                    txn.add_header('BIMI-Location', libmime.foldLines(bimiLocation, 160));
                }
            }
        } catch (err) {
            txn.notes.bimiResult = { error: err };
            connection.logerror(plugin, err.message);
        }
    }

    const receivedChain = dkimResult?.headers?.parsed.filter(r => r.key === 'received').map(row => parseReceived(row.line));
    const receivedChainComment = []
        .concat(receivedChain || [])
        .slice(1)
        .reverse()
        .slice(0, 5)
        .map(entry => entry?.by?.comment)
        .filter(value => value)
        .join(', ');

    for (const result of dkimResult?.results || []) {
        if (result.info) {
            connection.auth_results(result.info);
        }

        const signingHeaders = (result.signingHeaders?.keys || '')
            .toString()
            .split(':')
            .map(e => e.toLowerCase().trim());

        plugin.loggelf({
            short_message: '[DKIM] ' + result.status?.result,
            _queue_id: queueId,
            _mail_action: 'dkim_verify',
            _dkim_envelope_from: dkimResult?.envelopeFrom,
            _dkim_header_from: dkimResult?.headerFrom && [].concat(dkimResult?.headerFrom).join(', '),
            _dkim_info: result.info,
            _dkim_status: result.status?.result,
            _dkim_length_limited: result.canonBodyLengthLimited ? 'yes' : 'no',
            _dkim_over_sized: result.status?.underSized,
            _dkim_aligned: result.status?.aligned,
            _dkim_signing_domain: result.signingDomain,
            _dkim_selector: result.selector,
            _dkim_algo: result.algo,
            _dkim_mod_len: result.modulusLength,
            _dkim_canon_header: result.format?.split('/').shift(),
            _dkim_canon_body: result.format?.split('/').pop(),
            _dkim_body_size_source: result.sourceBodyLength,
            _dkim_body_size_canon: result.canonBodyLengthTotal,
            _dkim_body_size_limit: result.canonBodyLengthLimited && result.canonBodyLengthLimit,
            _dkim_canon_mime_start: result.mimeStructureStart,
            _dkim_signing_headers: signingHeaders.join(','),
            _dkim_signing_headers_content_type: signingHeaders.includes('content-type') ? 'yes' : 'no',
            _spf_status: txn.notes.spfResult?.status?.result,
            _spf_domain: txn.notes.spfResult?.domain,
            _dmarc_status: dmarcResult?.status?.result,
            _dmarc_spf_aligned: dmarcResult?.alignment?.spf?.result,
            _bimi_status: bimiResult?.status?.result,
            _bimi_comment: bimiResult?.status?.comment,
            _bimi_vmc: bimiResult?.status?.result === 'pass' && (bimiResult?.authority ? 'yes' : 'no'),
            _content_type_count: contentTypeHeaders.length,
            _content_type_boundary: contentTypeHeaders.length ? contentTypeHeaders.at(-1)?.params?.boundary?.substr(0, 20) : null,
            _received_by_comment: receivedChainComment
        });
    }

    if (txn.notes?.bimiResult?.status?.result === 'pass') {
        const cachedBimiResult = txn.notes.bimiResult;
        let bimiInfo = cachedBimiResult.info || '';

        const bimiResolution = {
            short_message: `[BIMI] ${cachedBimiResult.status?.header?.d}`,
            _queue_id: queueId,
            _bimi_domain: cachedBimiResult.status?.header?.d
        };

        try {
            const bimiData = await plugin.bimiHandler.getInfo(cachedBimiResult);
            if (bimiData?._id) {
                txn.notes.bimi = bimiData?._id;

                bimiResolution._has_bimi = 'yes';
                bimiResolution._bimi_cached_id = bimiData?._id.toString();
                bimiResolution._bimi_type = bimiData?.type;
                bimiResolution._bimi_url = bimiData?.url;
                bimiResolution._bimi_source = bimiData?.source;

                if (bimiData.vmc && bimiData.vmc.logoFile) {
                    const bimiIndicator = bimiData.vmc.logoFile;

                    let wrappedBimiIndicator = bimiIndicator.substring(0, 49);
                    for (let i = 49; i < bimiIndicator.length; i += 64) {
                        wrappedBimiIndicator += `\r\n ${bimiIndicator.substring(i, i + 64)}`;
                    }

                    txn.add_header('BIMI-Indicator', wrappedBimiIndicator);
                }

                if (bimiData.info) {
                    bimiInfo = [bimiInfo, bimiData.info].filter(entry => entry).join(' ');
                }
            }
        } catch (err) {
            bimiResolution._failure = 'yes';
            bimiResolution._error = err.message;
            bimiResolution._err_code = err.code;
            connection.logerror(plugin, err.message);
        }

        if (bimiInfo) {
            connection.auth_results(bimiInfo);
            bimiResolution._bimi_info = bimiInfo;
        }

        plugin.loggelf(bimiResolution);
    }
}

module.exports = { hookMail, hookDataPost };
