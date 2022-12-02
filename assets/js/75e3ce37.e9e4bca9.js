"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[3088],{3905:(e,t,r)=>{r.d(t,{Zo:()=>s,kt:()=>m});var i=r(7294);function o(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function n(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);t&&(i=i.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,i)}return r}function p(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?n(Object(r),!0).forEach((function(t){o(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):n(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function a(e,t){if(null==e)return{};var r,i,o=function(e,t){if(null==e)return{};var r,i,o={},n=Object.keys(e);for(i=0;i<n.length;i++)r=n[i],t.indexOf(r)>=0||(o[r]=e[r]);return o}(e,t);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);for(i=0;i<n.length;i++)r=n[i],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(o[r]=e[r])}return o}var l=i.createContext({}),c=function(e){var t=i.useContext(l),r=t;return e&&(r="function"==typeof e?e(t):p(p({},t),e)),r},s=function(e){var t=c(e.components);return i.createElement(l.Provider,{value:t},e.children)},d="mdxType",f={inlineCode:"code",wrapper:function(e){var t=e.children;return i.createElement(i.Fragment,{},t)}},u=i.forwardRef((function(e,t){var r=e.components,o=e.mdxType,n=e.originalType,l=e.parentName,s=a(e,["components","mdxType","originalType","parentName"]),d=c(r),u=o,m=d["".concat(l,".").concat(u)]||d[u]||f[u]||n;return r?i.createElement(m,p(p({ref:t},s),{},{components:r})):i.createElement(m,p({ref:t},s))}));function m(e,t){var r=arguments,o=t&&t.mdxType;if("string"==typeof e||o){var n=r.length,p=new Array(n);p[0]=u;var a={};for(var l in t)hasOwnProperty.call(t,l)&&(a[l]=t[l]);a.originalType=e,a[d]="string"==typeof e?e:o,p[1]=a;for(var c=2;c<n;c++)p[c]=r[c];return i.createElement.apply(null,p)}return i.createElement.apply(null,r)}u.displayName="MDXCreateElement"},9900:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>l,contentTitle:()=>p,default:()=>d,frontMatter:()=>n,metadata:()=>a,toc:()=>c});var i=r(7462),o=(r(7294),r(3905));const n={id:"prof",title:"prof",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"prof",description:"Profile commands",last_update:{date:new Date("2022-11-30T19:14:58.000Z"),author:"blacktop"}},p=void 0,a={unversionedId:"cli/ipsw/idev/prof/prof",id:"cli/ipsw/idev/prof/prof",title:"prof",description:"Profile commands",source:"@site/docs/cli/ipsw/idev/prof/prof.md",sourceDirName:"cli/ipsw/idev/prof",slug:"/cli/ipsw/idev/prof/",permalink:"/ipsw/docs/cli/ipsw/idev/prof/",draft:!1,editUrl:"https://github.com/blacktop/ipsw/tree/master/www/docs/cli/ipsw/idev/prof/prof.md",tags:[],version:"current",frontMatter:{id:"prof",title:"prof",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"prof",description:"Profile commands",last_update:{date:"2022-11-30T19:14:58.000Z",author:"blacktop"}},sidebar:"cli",previous:{title:"pcap",permalink:"/ipsw/docs/cli/ipsw/idev/pcap"},next:{title:"cloud",permalink:"/ipsw/docs/cli/ipsw/idev/prof/cloud"}},l={},c=[{value:"ipsw idev prof",id:"ipsw-idev-prof",level:2},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3}],s={toc:c};function d(e){let{components:t,...r}=e;return(0,o.kt)("wrapper",(0,i.Z)({},s,r,{components:t,mdxType:"MDXLayout"}),(0,o.kt)("h2",{id:"ipsw-idev-prof"},"ipsw idev prof"),(0,o.kt)("p",null,"Profile commands"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},"ipsw idev prof [flags]\n")),(0,o.kt)("h3",{id:"options"},"Options"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},"  -h, --help   help for prof\n")),(0,o.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},"      --color           colorize output\n      --config string   config file (default is $HOME/.ipsw.yaml)\n  -u, --udid string     Device UniqueDeviceID to connect to\n  -V, --verbose         verbose output\n")),(0,o.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,o.kt)("ul",null,(0,o.kt)("li",{parentName:"ul"},(0,o.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/idev"},"ipsw idev"),"\t - USB connected device commands"),(0,o.kt)("li",{parentName:"ul"},(0,o.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/idev/prof/cloud"},"ipsw idev prof cloud"),"\t - Get cloud configuration"),(0,o.kt)("li",{parentName:"ul"},(0,o.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/idev/prof/install"},"ipsw idev prof install"),"\t - Install profile"),(0,o.kt)("li",{parentName:"ul"},(0,o.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/idev/prof/ls"},"ipsw idev prof ls"),"\t - List installed provision profiles"),(0,o.kt)("li",{parentName:"ul"},(0,o.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/idev/prof/rm"},"ipsw idev prof rm"),"\t - Remove profile by name"),(0,o.kt)("li",{parentName:"ul"},(0,o.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/idev/prof/wifi"},"ipsw idev prof wifi"),"\t - Change Wi-Fi power state")))}d.isMDXComponent=!0}}]);