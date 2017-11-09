var fs = require('fs');
var pem2jwk = require('./');
var dir = fs.readdirSync('./fixtures');

for (let file of dir) {
  console.log(file);
  console.log(pem2jwk(fs.readFileSync(`fixtures/${file}`)));
}