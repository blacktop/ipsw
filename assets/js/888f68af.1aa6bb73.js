"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[1885],{3905:(e,t,r)=>{r.d(t,{Zo:()=>c,kt:()=>u});var n=r(7294);function i(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function a(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function o(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?a(Object(r),!0).forEach((function(t){i(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):a(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function l(e,t){if(null==e)return{};var r,n,i=function(e,t){if(null==e)return{};var r,n,i={},a=Object.keys(e);for(n=0;n<a.length;n++)r=a[n],t.indexOf(r)>=0||(i[r]=e[r]);return i}(e,t);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);for(n=0;n<a.length;n++)r=a[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(i[r]=e[r])}return i}var s=n.createContext({}),d=function(e){var t=n.useContext(s),r=t;return e&&(r="function"==typeof e?e(t):o(o({},t),e)),r},c=function(e){var t=d(e.components);return n.createElement(s.Provider,{value:t},e.children)},p={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},f=n.forwardRef((function(e,t){var r=e.components,i=e.mdxType,a=e.originalType,s=e.parentName,c=l(e,["components","mdxType","originalType","parentName"]),f=d(r),u=i,m=f["".concat(s,".").concat(u)]||f[u]||p[u]||a;return r?n.createElement(m,o(o({ref:t},c),{},{components:r})):n.createElement(m,o({ref:t},c))}));function u(e,t){var r=arguments,i=t&&t.mdxType;if("string"==typeof e||i){var a=r.length,o=new Array(a);o[0]=f;var l={};for(var s in t)hasOwnProperty.call(t,s)&&(l[s]=t[s]);l.originalType=e,l.mdxType="string"==typeof e?e:i,o[1]=l;for(var d=2;d<a;d++)o[d]=r[d];return n.createElement.apply(null,o)}return n.createElement.apply(null,r)}f.displayName="MDXCreateElement"},7514:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>s,contentTitle:()=>o,default:()=>p,frontMatter:()=>a,metadata:()=>l,toc:()=>d});var n=r(7462),i=(r(7294),r(3905));const a={id:"xref",title:"xref",hide_title:!0,sidebar_label:"xref",description:"\ud83d\udea7 [WIP] Find all cross references to an address",last_update:{date:new Date("2022-11-24T20:58:11.000Z"),author:"blacktop"}},o=void 0,l={unversionedId:"cli/ipsw/dyld/xref",id:"cli/ipsw/dyld/xref",title:"xref",description:"\ud83d\udea7 [WIP] Find all cross references to an address",source:"@site/docs/cli/ipsw/dyld/xref.md",sourceDirName:"cli/ipsw/dyld",slug:"/cli/ipsw/dyld/xref",permalink:"/docs/cli/ipsw/dyld/xref",draft:!1,editUrl:"https://github.com/blacktop/ipsw/tree/master/www/docs/cli/ipsw/dyld/xref.md",tags:[],version:"current",frontMatter:{id:"xref",title:"xref",hide_title:!0,sidebar_label:"xref",description:"\ud83d\udea7 [WIP] Find all cross references to an address",last_update:{date:"2022-11-24T20:58:11.000Z",author:"blacktop"}},sidebar:"cli",previous:{title:"webkit",permalink:"/docs/cli/ipsw/dyld/webkit"},next:{title:"ent",permalink:"/docs/cli/ipsw/ent"}},s={},d=[{value:"ipsw dyld xref",id:"ipsw-dyld-xref",level:2},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3}],c={toc:d};function p(e){let{components:t,...r}=e;return(0,i.kt)("wrapper",(0,n.Z)({},c,r,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("h2",{id:"ipsw-dyld-xref"},"ipsw dyld xref"),(0,i.kt)("p",null,"\ud83d\udea7 ","[WIP]"," Find all cross references to an address"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"ipsw dyld xref <dyld_shared_cache> <vaddr> [flags]\n")),(0,i.kt)("h3",{id:"options"},"Options"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"  -a, --all            Search all images\n      --cache string   Path to .a2s addr to sym cache file (speeds up analysis)\n  -h, --help           help for xref\n  -i, --image string   Dylib image to search\n      --imports        Search all other dylibs that import the dylib containing the xref src\n  -s, --slide uint     dyld_shared_cache slide to apply (not supported yet)\n")),(0,i.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"      --color           colorize output\n      --config string   config file (default is $HOME/.ipsw.yaml)\n  -V, --verbose         verbose output\n")),(0,i.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/dyld"},"ipsw dyld"),"\t - Parse dyld_shared_cache")))}p.isMDXComponent=!0}}]);