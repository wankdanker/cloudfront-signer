module.exports = safeBase64;


function safeBase64(str) {
    return str.replace(/\+/g, '-')
        .replace(/=/g, '_')
        .replace(/\//g, '~');        
}