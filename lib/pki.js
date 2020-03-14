/**
 * Javascript implementation of a basic Public Key Infrastructure, including
 * support for RSA public and private keys.
 *
 * @author Dave Longley
 *
 * Copyright (c) 2010-2013 Digital Bazaar, Inc.
 */
var forge = require('./forge');
require('./asn1');
require('./oids');
// require('./pbe');
// require('./pem');
// require('./pbkdf2');
// require('./pkcs12');
// require('./pss');
require('./rsa');
require('./util');
// require('./x509');

// shortcut for asn.1 API
var asn1 = forge.asn1;

/* Public Key Infrastructure (PKI) implementation. */
var pki = module.exports = forge.pki = forge.pki || {};

pki.privateKeyToPem = function(key, maxline) {
  // convert to ASN.1, then DER, then PEM-encode
  var msg = {
    type: 'RSA PRIVATE KEY',
    body: asn1.toDer(pki.privateKeyToAsn1(key)).getBytes()
  };
  return forge.pem.encode(msg, {maxline: maxline});
};
pki.publicKeyToPem = function(key, maxline) {
  // convert to ASN.1, then DER, then PEM-encode
  var msg = {
    type: 'PUBLIC KEY',
    body: asn1.toDer(pki.publicKeyToAsn1(key)).getBytes()
  };
  return forge.pem.encode(msg, {maxline: maxline});
};
