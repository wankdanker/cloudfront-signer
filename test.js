const CloudFrontSigner = require('./lib/cloudfront-signer');
const signer = new CloudFrontSigner({
    key : process.env.CF_KEY
    , keyPairId : process.env.CF_KEY_PAIR_ID
});

console.log(signer.sign('some cloudfront distribution URL'));