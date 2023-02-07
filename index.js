const Koa = require('koa');
const app = new Koa();
const Router = require('@koa/router');
const router = new Router();
var ESAPI = require('node-esapi');

function handleHrefXss (url) {
  if (/^(https:\/\/)|(http:\/\/)|(\/\/)/.test(url)) {
    return `//${url}`
  }
  return url
} 

router.get('/', (ctx, next) => {
  // HTML注入XSS
  const htmlXSS = '<script>alert("HTML XSS")</script>' // ESAPI.encoder().encodeForHTML('<script>alert("XSS")</script>');
  // CSS注入XSS，IE 7 下复现
  const cssXSS=  `expression(alert('CSS XSS'),1)` // ESAPI.encoder().encodeForCSS(`expression(alert('CSS XSS'),1)`)
  // HTML Attribute注入XSS, 漏洞复现访问 http://127.0.0.1:3000/?cb=javascript:alert(123)
  const cbParam = ctx.request.url.slice(ctx.request.url.indexOf('cb') + 3)
  const parsedCb =  cbParam // handleHrefXss(cbParam)
  console.log(cbParam)
  // Javascript 注入XSS
  const jsXSS = `";alert('JS XSS');"`; // ESAPI.encoder().encodeForJavaScript(`";alert('JS XSS');"`)
  // base64 中注入XSS
  const base64XSS = `data:text/html;base64,PHNjcmlwdD5hbGVydCgnYmFzZTY0IFhTUycpPC9zY3JpcHQ+` // ESAPI.encoder().encodeForBase64(`data:text/html;base64,PHNjcmlwdD5hbGVydCgnYmFzZTY0IFhTUycpPC9zY3JpcHQ+`)
  ctx.body = `
    <div>${htmlXSS}</div>
    <a href=${parsedCb}>HTML Attribute XSS</a>
    <div style="height:${cssXSS}"></div>
    <h2>Base64 XSS: </h2>
    <iframe src=${base64XSS}>Base64 XSS</iframe>
    <script>
      var a = "${jsXSS}"
    </script>
  `;
});

app
  .use(router.routes())
  .use(router.allowedMethods());

app.listen(3000, () => {
  console.log('started on 3000 port')
});