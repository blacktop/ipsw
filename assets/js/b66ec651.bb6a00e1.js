"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[5569],{3905:(e,t,r)=>{r.d(t,{Zo:()=>s,kt:()=>f});var n=r(7294);function a(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function i(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function d(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?i(Object(r),!0).forEach((function(t){a(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):i(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function o(e,t){if(null==e)return{};var r,n,a=function(e,t){if(null==e)return{};var r,n,a={},i=Object.keys(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||(a[r]=e[r]);return a}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(a[r]=e[r])}return a}var l=n.createContext({}),p=function(e){var t=n.useContext(l),r=t;return e&&(r="function"==typeof e?e(t):d(d({},t),e)),r},s=function(e){var t=p(e.components);return n.createElement(l.Provider,{value:t},e.children)},c="mdxType",u={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},m=n.forwardRef((function(e,t){var r=e.components,a=e.mdxType,i=e.originalType,l=e.parentName,s=o(e,["components","mdxType","originalType","parentName"]),c=p(r),m=a,f=c["".concat(l,".").concat(m)]||c[m]||u[m]||i;return r?n.createElement(f,d(d({ref:t},s),{},{components:r})):n.createElement(f,d({ref:t},s))}));function f(e,t){var r=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var i=r.length,d=new Array(i);d[0]=m;var o={};for(var l in t)hasOwnProperty.call(t,l)&&(o[l]=t[l]);o.originalType=e,o[c]="string"==typeof e?e:a,d[1]=o;for(var p=2;p<i;p++)d[p]=r[p];return n.createElement.apply(null,d)}return n.createElement.apply(null,r)}m.displayName="MDXCreateElement"},5783:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>l,contentTitle:()=>d,default:()=>c,frontMatter:()=>i,metadata:()=>o,toc:()=>p});var n=r(7462),a=(r(7294),r(3905));const i={id:"dump",title:"dump",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"dump",description:"Dump dyld_shared_cache data at given virtual address",last_update:{date:new Date("2022-11-30T19:14:58.000Z"),author:"blacktop"}},d=void 0,o={unversionedId:"cli/ipsw/dyld/dump",id:"cli/ipsw/dyld/dump",title:"dump",description:"Dump dyld_shared_cache data at given virtual address",source:"@site/docs/cli/ipsw/dyld/dump.md",sourceDirName:"cli/ipsw/dyld",slug:"/cli/ipsw/dyld/dump",permalink:"/ipsw/docs/cli/ipsw/dyld/dump",draft:!1,editUrl:"https://github.com/blacktop/ipsw/tree/master/www/docs/cli/ipsw/dyld/dump.md",tags:[],version:"current",frontMatter:{id:"dump",title:"dump",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"dump",description:"Dump dyld_shared_cache data at given virtual address",last_update:{date:"2022-11-30T19:14:58.000Z",author:"blacktop"}},sidebar:"cli",previous:{title:"disass",permalink:"/ipsw/docs/cli/ipsw/dyld/disass"},next:{title:"extract",permalink:"/ipsw/docs/cli/ipsw/dyld/extract"}},l={},p=[{value:"ipsw dyld dump",id:"ipsw-dyld-dump",level:2},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3}],s={toc:p};function c(e){let{components:t,...r}=e;return(0,a.kt)("wrapper",(0,n.Z)({},s,r,{components:t,mdxType:"MDXLayout"}),(0,a.kt)("h2",{id:"ipsw-dyld-dump"},"ipsw dyld dump"),(0,a.kt)("p",null,"Dump dyld_shared_cache data at given virtual address"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre"},"ipsw dyld dump <dyld_shared_cache> <address> [flags]\n")),(0,a.kt)("h3",{id:"options"},"Options"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre"},"  -a, --addr            Output as addresses/uint64s\n  -b, --bytes           Output as bytes\n  -c, --count uint      The number of total items to display\n  -h, --help            help for dump\n  -o, --output string   Output to a file\n  -s, --size uint       Size of data in bytes\n")),(0,a.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre"},"      --color           colorize output\n      --config string   config file (default is $HOME/.ipsw.yaml)\n  -V, --verbose         verbose output\n")),(0,a.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,a.kt)("ul",null,(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/dyld"},"ipsw dyld"),"\t - Parse dyld_shared_cache")))}c.isMDXComponent=!0}}]);