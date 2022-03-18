const crypto = require('crypto');
const safeBase64 = require('./safe-base64');

class CloudFrontSigner {
    /**
     * Creates an instance of CloudFrontSigner.
     * @param {object} opts
     * @param {string} opts.key
     * @param {string} opts.keyPairId
     * @param {number} [opts.expirationMs=7200000]    default access expiration in milliseconds
     * 
     * @memberof CloudFrontSigner
     */
    constructor (opts) {
        opts = opts || {};

        this.key = opts.key;
        this.keyPairId = opts.keyPairId;
        this.expirationMs = opts.expirationMs || 7200000;
    }

    /**
     *
     *
     * @param {string} url
     * @param {Date} expiration
     * @return {Object} 
     * @memberof CloudFrontSigner
     */
    sign(url, expiration) {
        const expirationSeconds = this.getExpirationSeconds(expiration);
        const policy = this.getPolicy(url, expirationSeconds);
        const policyJson = this.getPolicyJson(policy);
        const policySignatureBase64 = this.getSignedPolicy(policyJson);
        const policyJsonBase64 = this.getPolicyJsonBase64(policyJson);

        const parsedUrl = new URL(url);

        parsedUrl.searchParams.set('Expires', expirationSeconds);
        parsedUrl.searchParams.set('Signature', policySignatureBase64);
        parsedUrl.searchParams.set('Key-Pair-Id', this.keyPairId);

        const signedCannedUrl = parsedUrl.toString().replace(/%7E/g,'~').replace(/__$/, '');

        parsedUrl.searchParams.delete('Expires');
        parsedUrl.searchParams.set('Policy', policyJsonBase64);

        const signedCustomUrl = parsedUrl.toString().replace(/%7E/g,'~').replace(/__$/, '');

        return {
            url
            , expirationSeconds
            , policy
            , policyJsonBase64
            , policySignatureBase64
            , signedCannedUrl
            , signedCustomUrl
            , keyPairId: this.keyPairId
        };
    }

    /**
     *
     *
     * @param {String} url
     * @param {Date} [expiration]
     * @return {Object} 
     * 
     * @memberof CloudFrontSigner
     */
    getPolicy (url, expirationSeconds) {
        const policy = {
            'Statement': [{
                'Resource': url,
                'Condition': {
                    'DateLessThan': {
                        'AWS:EpochTime': expirationSeconds
                    }
                }
            }]
        };

        return policy;
    }

    /**
     *
     *
     * @param {Object} policy
     * @return {string} 
     * @memberof CloudFrontSigner
     */
    getPolicyJson (policy) {
        return JSON.stringify(policy);
    }

    /**
     *
     *
     * @param {string} policyJson
     * @return {string} 
     * @memberof CloudFrontSigner
     */
    getPolicyJsonBase64 (policyJson) {
        return safeBase64(Buffer.from(policyJson).toString('base64'));
    }

    /**
     *
     *
     * @param {string} policyJson
     * @return {string} 
     * @memberof CloudFrontSigner
     */
    getSignedPolicy (policyJson) {
        return safeBase64(crypto.createSign('RSA-SHA1')
                .update(policyJson)
                .sign(this.key, 'base64'));
    }

    /**
     *
     *
     * @param {Date} date
     * @return {number} 
     * @memberof CloudFrontSigner
     */
    getExpirationSeconds(date) {
        if (!date) {
            date = new Date();
            date.setMilliseconds(date.getMilliseconds() + this.expirationMs);
        }

        return Math.floor(date.getTime() / 1000);
    }
}

module.exports = CloudFrontSigner;