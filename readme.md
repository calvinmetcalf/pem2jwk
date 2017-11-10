pem2jwk
====

Convert a PEM key into a JWK (key).  Works for both RSA key and Elliptical Curve Keys but not DSA keys.

```js
var pem2jwk = require('pem2jwt');
var jwt = pem2jwk(fs.readFileSync('./path/to/key.pem'));
```
