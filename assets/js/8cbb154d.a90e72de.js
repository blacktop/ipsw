"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[9159],{3905:(e,t,r)=>{r.d(t,{Zo:()=>p,kt:()=>y});var n=r(7294);function i(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function a(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function o(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?a(Object(r),!0).forEach((function(t){i(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):a(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function s(e,t){if(null==e)return{};var r,n,i=function(e,t){if(null==e)return{};var r,n,i={},a=Object.keys(e);for(n=0;n<a.length;n++)r=a[n],t.indexOf(r)>=0||(i[r]=e[r]);return i}(e,t);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);for(n=0;n<a.length;n++)r=a[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(i[r]=e[r])}return i}var l=n.createContext({}),d=function(e){var t=n.useContext(l),r=t;return e&&(r="function"==typeof e?e(t):o(o({},t),e)),r},p=function(e){var t=d(e.components);return n.createElement(l.Provider,{value:t},e.children)},c="mdxType",u={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},m=n.forwardRef((function(e,t){var r=e.components,i=e.mdxType,a=e.originalType,l=e.parentName,p=s(e,["components","mdxType","originalType","parentName"]),c=d(r),m=i,y=c["".concat(l,".").concat(m)]||c[m]||u[m]||a;return r?n.createElement(y,o(o({ref:t},p),{},{components:r})):n.createElement(y,o({ref:t},p))}));function y(e,t){var r=arguments,i=t&&t.mdxType;if("string"==typeof e||i){var a=r.length,o=new Array(a);o[0]=m;var s={};for(var l in t)hasOwnProperty.call(t,l)&&(s[l]=t[l]);s.originalType=e,s[c]="string"==typeof e?e:i,o[1]=s;for(var d=2;d<a;d++)o[d]=r[d];return n.createElement.apply(null,o)}return n.createElement.apply(null,r)}m.displayName="MDXCreateElement"},5616:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>l,contentTitle:()=>o,default:()=>u,frontMatter:()=>a,metadata:()=>s,toc:()=>d});var n=r(7462),i=(r(7294),r(3905));const a={id:"a2s",title:"a2s",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"a2s",description:"Lookup symbol at unslid address"},o=void 0,s={unversionedId:"cli/ipsw/dyld/a2s",id:"cli/ipsw/dyld/a2s",title:"a2s",description:"Lookup symbol at unslid address",source:"@site/docs/cli/ipsw/dyld/a2s.md",sourceDirName:"cli/ipsw/dyld",slug:"/cli/ipsw/dyld/a2s",permalink:"/ipsw/docs/cli/ipsw/dyld/a2s",draft:!1,editUrl:"https://github.com/blacktop/ipsw/tree/master/www/docs/cli/ipsw/dyld/a2s.md",tags:[],version:"current",frontMatter:{id:"a2s",title:"a2s",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"a2s",description:"Lookup symbol at unslid address"},sidebar:"cli",previous:{title:"a2o",permalink:"/ipsw/docs/cli/ipsw/dyld/a2o"},next:{title:"disass",permalink:"/ipsw/docs/cli/ipsw/dyld/disass"}},l={},d=[{value:"ipsw dyld a2s",id:"ipsw-dyld-a2s",level:2},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3}],p={toc:d},c="wrapper";function u(e){let{components:t,...r}=e;return(0,i.kt)(c,(0,n.Z)({},p,r,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("h2",{id:"ipsw-dyld-a2s"},"ipsw dyld a2s"),(0,i.kt)("p",null,"Lookup symbol at unslid address"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"ipsw dyld a2s <dyld_shared_cache> <vaddr> [flags]\n")),(0,i.kt)("h3",{id:"options"},"Options"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"      --cache string   Path to .a2s addr to sym cache file (speeds up analysis)\n  -h, --help           help for a2s\n  -i, --image          Only lookup address's dyld_shared_cache mapping\n  -m, --mapping        Only lookup address's image segment/section\n  -s, --slide uint     dyld_shared_cache slide to apply\n")),(0,i.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"      --color           colorize output\n      --config string   config file (default is $HOME/.ipsw/config.yaml)\n  -V, --verbose         verbose output\n")),(0,i.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/dyld"},"ipsw dyld"),"\t - Parse dyld_shared_cache")))}u.isMDXComponent=!0}}]);