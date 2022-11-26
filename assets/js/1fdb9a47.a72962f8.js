"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[2410],{3905:(e,t,r)=>{r.d(t,{Zo:()=>c,kt:()=>d});var n=r(7294);function l(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function i(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function a(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?i(Object(r),!0).forEach((function(t){l(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):i(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function o(e,t){if(null==e)return{};var r,n,l=function(e,t){if(null==e)return{};var r,n,l={},i=Object.keys(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||(l[r]=e[r]);return l}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(l[r]=e[r])}return l}var s=n.createContext({}),p=function(e){var t=n.useContext(s),r=t;return e&&(r="function"==typeof e?e(t):a(a({},t),e)),r},c=function(e){var t=p(e.components);return n.createElement(s.Provider,{value:t},e.children)},k={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},u=n.forwardRef((function(e,t){var r=e.components,l=e.mdxType,i=e.originalType,s=e.parentName,c=o(e,["components","mdxType","originalType","parentName"]),u=p(r),d=l,m=u["".concat(s,".").concat(d)]||u[d]||k[d]||i;return r?n.createElement(m,a(a({ref:t},c),{},{components:r})):n.createElement(m,a({ref:t},c))}));function d(e,t){var r=arguments,l=t&&t.mdxType;if("string"==typeof e||l){var i=r.length,a=new Array(i);a[0]=u;var o={};for(var s in t)hasOwnProperty.call(t,s)&&(o[s]=t[s]);o.originalType=e,o.mdxType="string"==typeof e?e:l,a[1]=o;for(var p=2;p<i;p++)a[p]=r[p];return n.createElement.apply(null,a)}return n.createElement.apply(null,r)}u.displayName="MDXCreateElement"},8071:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>s,contentTitle:()=>a,default:()=>k,frontMatter:()=>i,metadata:()=>o,toc:()=>p});var n=r(7462),l=(r(7294),r(3905));const i={id:"kernel",title:"kernel",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"kernel",description:"Parse kernelcache",last_update:{date:new Date("2022-11-26T01:20:31.000Z"),author:"blacktop"}},a=void 0,o={unversionedId:"cli/ipsw/kernel/kernel",id:"cli/ipsw/kernel/kernel",title:"kernel",description:"Parse kernelcache",source:"@site/docs/cli/ipsw/kernel/kernel.md",sourceDirName:"cli/ipsw/kernel",slug:"/cli/ipsw/kernel/",permalink:"/ipsw/docs/cli/ipsw/kernel/",draft:!1,editUrl:"https://github.com/blacktop/ipsw/tree/master/www/docs/cli/ipsw/kernel/kernel.md",tags:[],version:"current",frontMatter:{id:"kernel",title:"kernel",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"kernel",description:"Parse kernelcache",last_update:{date:"2022-11-26T01:20:31.000Z",author:"blacktop"}},sidebar:"cli",previous:{title:"info",permalink:"/ipsw/docs/cli/ipsw/info"},next:{title:"ctfdump",permalink:"/ipsw/docs/cli/ipsw/kernel/ctfdump"}},s={},p=[{value:"ipsw kernel",id:"ipsw-kernel",level:2},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3}],c={toc:p};function k(e){let{components:t,...r}=e;return(0,l.kt)("wrapper",(0,n.Z)({},c,r,{components:t,mdxType:"MDXLayout"}),(0,l.kt)("h2",{id:"ipsw-kernel"},"ipsw kernel"),(0,l.kt)("p",null,"Parse kernelcache"),(0,l.kt)("pre",null,(0,l.kt)("code",{parentName:"pre"},"ipsw kernel [flags]\n")),(0,l.kt)("h3",{id:"options"},"Options"),(0,l.kt)("pre",null,(0,l.kt)("code",{parentName:"pre"},"  -h, --help   help for kernel\n")),(0,l.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,l.kt)("pre",null,(0,l.kt)("code",{parentName:"pre"},"      --color           colorize output\n      --config string   config file (default is $HOME/.ipsw.yaml)\n  -V, --verbose         verbose output\n")),(0,l.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,l.kt)("ul",null,(0,l.kt)("li",{parentName:"ul"},(0,l.kt)("a",{parentName:"li",href:"/docs/cli/ipsw"},"ipsw"),"\t - Download and Parse IPSWs (and SO much more)"),(0,l.kt)("li",{parentName:"ul"},(0,l.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/kernel/ctfdump"},"ipsw kernel ctfdump"),"\t - Dump CTF info"),(0,l.kt)("li",{parentName:"ul"},(0,l.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/kernel/dec"},"ipsw kernel dec"),"\t - Decompress a kernelcache"),(0,l.kt)("li",{parentName:"ul"},(0,l.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/kernel/extract"},"ipsw kernel extract"),"\t - Extract and decompress a kernelcache from IPSW"),(0,l.kt)("li",{parentName:"ul"},(0,l.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/kernel/kexts"},"ipsw kernel kexts"),"\t - List kernel extentions"),(0,l.kt)("li",{parentName:"ul"},(0,l.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/kernel/sbopts"},"ipsw kernel sbopts"),"\t - List kernel sandbox operations"),(0,l.kt)("li",{parentName:"ul"},(0,l.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/kernel/symbolsets"},"ipsw kernel symbolsets"),"\t - Dump kernel symbolsets"),(0,l.kt)("li",{parentName:"ul"},(0,l.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/kernel/syscall"},"ipsw kernel syscall"),"\t - Dump kernelcache syscalls"),(0,l.kt)("li",{parentName:"ul"},(0,l.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/kernel/version"},"ipsw kernel version"),"\t - Dump kernelcache version")))}k.isMDXComponent=!0}}]);