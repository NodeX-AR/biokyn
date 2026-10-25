/** Embedded browser script (<1.5KB). Usage: <form method="post" action="/contact" data-biokyn="contact"> */
export const CLIENT_SCRIPT =
  '(function(){var S=document.currentScript,B=S&&S.dataset.base||"/__biokyn",N="_biokyn",D={credentials:"same-origin",cache:"no-store"};' +
  'function U(f){var a=f.dataset.biokynAction||(f.getAttribute("method")||"POST").toUpperCase()+":"+new URL(f.getAttribute("action")||location.href,location.href).pathname;' +
  'return B+"/challenge?form="+encodeURIComponent(f.dataset.biokyn||f.id||"form")+"&action="+encodeURIComponent(a)}' +
  'function L(f,n){fetch(U(f),D).then(function(r){return r.json()}).then(function(d){var i;' +
  'if(d.token&&d.bootstrap){n<2&&L(f,n+1);return}' +
  'if(d.token){i=f.querySelector("input[name="+N+"]");if(!i){i=document.createElement("input");i.type="hidden";i.name=N;f.appendChild(i)}' +
  'i.value=d.token;f.dataset.k||setTimeout(function(){f.dataset.k=1},d.minAgeMs);' +
  'setTimeout(function(){L(f,0)},Math.max(1e4,d.ttlMs*.8))}' +
  'else if(d.retryAfterMs)setTimeout(function(){L(f,0)},d.retryAfterMs)}).catch(function(){setTimeout(function(){L(f,0)},5e3)})}' +
  'var P=fetch(B+"/challenge?form=boot&action=boot",D).catch(function(){});' +
  'function I(){document.querySelectorAll("form[data-biokyn]").forEach(function(f){' +
  'f.addEventListener("submit",function(e){f.dataset.k||e.preventDefault()},true);P.then(function(){L(f,0)})})}' +
  'document.readyState=="loading"?document.addEventListener("DOMContentLoaded",I):I()})();';

export function clientScriptTag(basePath = '/__biokyn'): string {
  const esc = basePath.replace(/[^A-Za-z0-9/_.-]/g, '');
  return `<script src="${esc}/client.js" data-base="${esc}" defer></script>`;
}
