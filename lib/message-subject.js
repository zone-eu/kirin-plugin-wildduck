'use strict';

const libmime = require('libmime');

module.exports = txn => {
    let subject = (txn?.header?.get?.('Subject') || '').toString();
    try {
        subject = libmime.decodeWords(subject).trim();
    } catch {
        // Keep the original value if decoding fails.
    }
    return subject;
};
