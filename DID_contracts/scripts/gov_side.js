const express = require('express');
const app = express();
const http = require('http').Server(app);
const io = require('socket.io')(http);
const fs = require('fs');
const cheerio = require('cheerio');
var speakeasy = require("speakeasy");
var QRCode = require('qrcode');
const querystring = require('querystring');
const cors = require('cors');
const {testWithOT }= require('./eth-x3dh/test');

var secret = speakeasy.generateSecret({length: 64});
// var secret = {};
// secret.base32='KVLDSURWGZNTAWZVFZBHG7KUKNYUM3CHO4STQLTMENCEMJSVFJYCG3SYI4XTGRC5MVLVOTK6OZ2VGL2EN5YUWY3GF4YD4I2KGZJXMRQ';
// secret.otpauth_url='otpauth://totp/SecretKey?secret=KVLDSURWGZNTAWZVFZBHG7KUKNYUM3CHO4STQLTMENCEMJSVFJYCG3SYI4XTGRC5MVLVOTK6OZ2VGL2EN5YUWY3GF4YD4I2KGZJXMRQ';
var url = speakeasy.otpauthURL({ secret: secret.ascii, label: 'OTP', algorithm: 'sha512' });

console.log(secret.base32);
console.log(secret.otpauth_url);

app.use(cors());


app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});


app.post('/downloadImage', (req, res) => {
  // 在这里可以添加对请求的处理逻辑，比如验证、过滤等

  // 响应数据给前端
  QRCode.toDataURL(url, function(err, data_url) {
    res.json({ image: data_url });
  });
});

app.post('/downloadSalt', (req, res) => {
  // 在这里可以添加对请求的处理逻辑，比如验证、过滤等

  // 响应数据给前端
  testWithOT().then((resolve, reject)=>{
    res.json({ salt: '0x'+resolve.toString() });
  });
});


app.post('/verifyOTP', function(req, res, next) {

  let requestData = '';

  req.on("data", (chunk) => {
    // 每次传输的数据块都会被追加到 requestData 变量中
    requestData += chunk;
  });

  req.on("end", () => {
    const parsedData = querystring.parse(requestData);
    const otp = parsedData.otp;
    var verified = speakeasy.totp.verify({ 
      secret: secret.base32,
      encoding: 'base32',
      token: otp,
      algorithm: 'sha512' });
    // 返回响应给客户端
    res.send('Result: ' + verified);
  });
});

http.listen(3000, () => {
  console.log('Server is running on port 5500');
});