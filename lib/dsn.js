'use strict';

class DSN {
    constructor(code, msg, subject, detail, defaultMessage) {
        this.code = Number(code) || 450;
        this.msg = msg || defaultMessage || '';
        this.cls = Number(String(this.code).charAt(0)) || 4;
        this.sub = Number(subject) || 0;
        this.det = Number(detail) || 0;
        this.default_msg = defaultMessage || '';
        this.reply = `${this.cls}.${this.sub}.${this.det} ${this.msg || this.default_msg}`.trim();
    }

    static create(code, msg, subject, detail) {
        return new DSN(code, msg, subject, detail);
    }

    static no_such_user(msg, code) {
        return new DSN(code || 550, msg || 'No such user', 1, 1, 'Bad destination mailbox address');
    }

    static addr_bad_dest_mbox(msg, code) {
        return new DSN(code || 550, msg || 'Bad destination mailbox address', 1, 1, 'Bad destination mailbox address');
    }

    static mbox_disabled(msg, code) {
        return new DSN(code || 550, msg || 'Mailbox disabled, not accepting messages', 2, 1, 'Mailbox disabled, not accepting messages');
    }

    static mbox_full(msg, code) {
        return new DSN(code || 450, msg || 'Mailbox full', 2, 2, 'Mailbox full');
    }
}

module.exports = DSN;
