// 可疑 JS 文件
eval("console.log('test')");
document.cookie = "track=true";
var ua = navigator.userAgent;
var ref = document.referrer;

// 十六进制编码 \x48\x65\x6c\x6c\x6f
// Unicode 编码 Hello
var a = "abc" + "def" + "ghi";

// hack exploit backdoor trojan malware keylogger

// Self-executing function
(function() { eval('x'); })();

// Base64 in comment: dGhpcyBpc250IHJlYWxseSBiYXNlNjQgZGF0YSwganVzdCBsb29rcyBsaWtlIGl0IHRob3VnaA==

var dynamicUrl = "https://external.ml/malware.js";
var ws = new WebSocket("wss://evil.xyz/ws");

function loadScript(url) {
    var s = document.createElement('script');
    s.src = url;
    document.body.appendChild(s);
}
