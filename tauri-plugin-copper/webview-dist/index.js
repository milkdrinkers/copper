function e(e,n,t,r){return new(t||(t=Promise))((function(o,i){function u(e){try{a(r.next(e))}catch(e){i(e)}}function c(e){try{a(r.throw(e))}catch(e){i(e)}}function a(e){var n;e.done?o(e.value):(n=e.value,n instanceof t?n:new t((function(e){e(n)}))).then(u,c)}a((r=r.apply(e,n||[])).next())}))}function n(e,n){var t,r,o,i,u={label:0,sent:function(){if(1&o[0])throw o[1];return o[1]},trys:[],ops:[]};return i={next:c(0),throw:c(1),return:c(2)},"function"==typeof Symbol&&(i[Symbol.iterator]=function(){return this}),i;function c(c){return function(a){return function(c){if(t)throw new TypeError("Generator is already executing.");for(;i&&(i=0,c[0]&&(u=0)),u;)try{if(t=1,r&&(o=2&c[0]?r.return:c[0]?r.throw||((o=r.return)&&o.call(r),0):r.next)&&!(o=o.call(r,c[1])).done)return o;switch(r=0,o&&(c=[2&c[0],o.value]),c[0]){case 0:case 1:o=c;break;case 4:return u.label++,{value:c[1],done:!1};case 5:u.label++,r=c[1],c=[0];continue;case 7:c=u.ops.pop(),u.trys.pop();continue;default:if(!(o=u.trys,(o=o.length>0&&o[o.length-1])||6!==c[0]&&2!==c[0])){u=0;continue}if(3===c[0]&&(!o||c[1]>o[0]&&c[1]<o[3])){u.label=c[1];break}if(6===c[0]&&u.label<o[1]){u.label=o[1],o=c;break}if(o&&u.label<o[2]){u.label=o[2],u.ops.push(c);break}o[2]&&u.ops.pop(),u.trys.pop();continue}c=n.call(e,u)}catch(e){c=[6,e],r=0}finally{t=o=0}if(5&c[0])throw c[1];return{value:c[0]?c[1]:void 0,done:!0}}([c,a])}}}var t=Object.defineProperty;function r(e,n=!1){let t=window.crypto.getRandomValues(new Uint32Array(1))[0],r=`_${t}`;return Object.defineProperty(window,r,{value:t=>(n&&Reflect.deleteProperty(window,r),null==e?void 0:e(t)),writable:!1,configurable:!0}),t}async function o(e,n={}){return new Promise(((t,o)=>{let i=r((e=>{t(e),Reflect.deleteProperty(window,`_${u}`)}),!0),u=r((e=>{o(e),Reflect.deleteProperty(window,`_${i}`)}),!0);window.__TAURI_IPC__({cmd:e,callback:i,error:u,...n})}))}function i(e,n="asset"){let t=encodeURIComponent(e);return navigator.userAgent.includes("Windows")?`https://${n}.localhost/${t}`:`${n}://localhost/${t}`}function u(){return e(this,void 0,void 0,(function(){return n(this,(function(e){switch(e.label){case 0:return[4,o("plugin:copper|get_auth_info")];case 1:return[2,e.sent()]}}))}))}function c(t){return e(this,void 0,void 0,(function(){return n(this,(function(e){switch(e.label){case 0:return[4,o("plugin:copper|get_ms_token",{authInfo:t})];case 1:return[2,e.sent()]}}))}))}function a(t){return e(this,void 0,void 0,(function(){return n(this,(function(e){switch(e.label){case 0:return[4,o("plugin:copper|refresh_ms_token",{authToken:t})];case 1:return[2,e.sent()]}}))}))}function l(t){return e(this,void 0,void 0,(function(){return n(this,(function(e){switch(e.label){case 0:return[4,o("plugin:copper|get_auth_data",{auth_info:t})];case 1:return[2,e.sent()]}}))}))}((e,n)=>{for(var r in n)t(e,r,{get:n[r],enumerable:!0})})({},{convertFileSrc:()=>i,invoke:()=>o,transformCallback:()=>r});export{l as getAuthData,u as getAuthenticationInfo,c as getMicrosoftToken,a as refreshAuthToken};
