'use strict';

const common = require('../common');
if (!common.hasCrypto)
    common.skip('missing crypto');

// const assert = require('assert');
const tls = require('tls');
const fixtures = require('../common/fixtures');

// The subject MUST NOT be ignored if no dNSName subject alternative name
// exists, even if other subject alternative names exist.
{
    const key = fixtures.readKey('irrelevant_san_correct_subject-key.pem');
    const cert = fixtures.readKey('irrelevant_san_correct_subject-cert.pem');
    // The hostname is the CN, but there is no dNSName SAN entry.
    const servername = 'good.example.com';
    // X509Certificate interface is not supported in v12.x & v14.x. Disable
    // checks for certX509.subject and certX509.subjectAltName with expected
    // value. The testcase is ported from v17.x
    //
    // const certX509 = new X509Certificate(cert);
    // assert.strictEqual(certX509.subject, `CN=${servername}`);
    // assert.strictEqual(certX509.subjectAltName, 'IP Address:1.2.3.4');
    // Connect to a server that uses the self-signed certificate.
    const server = tls.createServer({ key, cert }, common.mustCall((socket) => {
        socket.destroy();
        server.close();
    })).listen(common.mustCall(() => {
        const { port } = server.address();
        tls.connect(port, {
            ca: cert,
            servername,
        }, common.mustCall(() => {
            // Do nothing, the server will close the connection.
        }));
    }));
}
