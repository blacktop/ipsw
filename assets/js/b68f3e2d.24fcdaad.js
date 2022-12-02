"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[3860],{3905:(e,t,r)=>{r.d(t,{Zo:()=>c,kt:()=>b});var n=r(7294);function i(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function p(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function o(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?p(Object(r),!0).forEach((function(t){i(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):p(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function a(e,t){if(null==e)return{};var r,n,i=function(e,t){if(null==e)return{};var r,n,i={},p=Object.keys(e);for(n=0;n<p.length;n++)r=p[n],t.indexOf(r)>=0||(i[r]=e[r]);return i}(e,t);if(Object.getOwnPropertySymbols){var p=Object.getOwnPropertySymbols(e);for(n=0;n<p.length;n++)r=p[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(i[r]=e[r])}return i}var s=n.createContext({}),l=function(e){var t=n.useContext(s),r=t;return e&&(r="function"==typeof e?e(t):o(o({},t),e)),r},c=function(e){var t=l(e.components);return n.createElement(s.Provider,{value:t},e.children)},d="mdxType",u={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},m=n.forwardRef((function(e,t){var r=e.components,i=e.mdxType,p=e.originalType,s=e.parentName,c=a(e,["components","mdxType","originalType","parentName"]),d=l(r),m=i,b=d["".concat(s,".").concat(m)]||d[m]||u[m]||p;return r?n.createElement(b,o(o({ref:t},c),{},{components:r})):n.createElement(b,o({ref:t},c))}));function b(e,t){var r=arguments,i=t&&t.mdxType;if("string"==typeof e||i){var p=r.length,o=new Array(p);o[0]=m;var a={};for(var s in t)hasOwnProperty.call(t,s)&&(a[s]=t[s]);a.originalType=e,a[d]="string"==typeof e?e:i,o[1]=a;for(var l=2;l<p;l++)o[l]=r[l];return n.createElement.apply(null,o)}return n.createElement.apply(null,r)}m.displayName="MDXCreateElement"},3561:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>s,contentTitle:()=>o,default:()=>d,frontMatter:()=>p,metadata:()=>a,toc:()=>l});var n=r(7462),i=(r(7294),r(3905));const p={id:"springb",title:"springb",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"springb",description:"SpringBoard commands",last_update:{date:new Date("2022-11-30T19:14:58.000Z"),author:"blacktop"}},o=void 0,a={unversionedId:"cli/ipsw/idev/springb/springb",id:"cli/ipsw/idev/springb/springb",title:"springb",description:"SpringBoard commands",source:"@site/docs/cli/ipsw/idev/springb/springb.md",sourceDirName:"cli/ipsw/idev/springb",slug:"/cli/ipsw/idev/springb/",permalink:"/ipsw/docs/cli/ipsw/idev/springb/",draft:!1,editUrl:"https://github.com/blacktop/ipsw/tree/master/www/docs/cli/ipsw/idev/springb/springb.md",tags:[],version:"current",frontMatter:{id:"springb",title:"springb",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"springb",description:"SpringBoard commands",last_update:{date:"2022-11-30T19:14:58.000Z",author:"blacktop"}},sidebar:"cli",previous:{title:"screen",permalink:"/ipsw/docs/cli/ipsw/idev/screen"},next:{title:"icon",permalink:"/ipsw/docs/cli/ipsw/idev/springb/icon"}},s={},l=[{value:"ipsw idev springb",id:"ipsw-idev-springb",level:2},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3}],c={toc:l};function d(e){let{components:t,...r}=e;return(0,i.kt)("wrapper",(0,n.Z)({},c,r,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("h2",{id:"ipsw-idev-springb"},"ipsw idev springb"),(0,i.kt)("p",null,"SpringBoard commands"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"ipsw idev springb [flags]\n")),(0,i.kt)("h3",{id:"options"},"Options"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"  -h, --help   help for springb\n")),(0,i.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"      --color           colorize output\n      --config string   config file (default is $HOME/.ipsw.yaml)\n  -u, --udid string     Device UniqueDeviceID to connect to\n  -V, --verbose         verbose output\n")),(0,i.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/idev"},"ipsw idev"),"\t - USB connected device commands"),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/idev/springb/icon"},"ipsw idev springb icon"),"\t - Dump application icon as PNG"),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/idev/springb/orient"},"ipsw idev springb orient"),"\t - Get screen orientation"),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/idev/springb/wallpaper"},"ipsw idev springb wallpaper"),"\t - Dump wallpaper as PNG")))}d.isMDXComponent=!0}}]);