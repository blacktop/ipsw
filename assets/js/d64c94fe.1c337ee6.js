"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[1248],{3905:(e,t,i)=>{i.d(t,{Zo:()=>s,kt:()=>u});var r=i(7294);function a(e,t,i){return t in e?Object.defineProperty(e,t,{value:i,enumerable:!0,configurable:!0,writable:!0}):e[t]=i,e}function n(e,t){var i=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),i.push.apply(i,r)}return i}function o(e){for(var t=1;t<arguments.length;t++){var i=null!=arguments[t]?arguments[t]:{};t%2?n(Object(i),!0).forEach((function(t){a(e,t,i[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(i)):n(Object(i)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(i,t))}))}return e}function c(e,t){if(null==e)return{};var i,r,a=function(e,t){if(null==e)return{};var i,r,a={},n=Object.keys(e);for(r=0;r<n.length;r++)i=n[r],t.indexOf(i)>=0||(a[i]=e[i]);return a}(e,t);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);for(r=0;r<n.length;r++)i=n[r],t.indexOf(i)>=0||Object.prototype.propertyIsEnumerable.call(e,i)&&(a[i]=e[i])}return a}var l=r.createContext({}),p=function(e){var t=r.useContext(l),i=t;return e&&(i="function"==typeof e?e(t):o(o({},t),e)),i},s=function(e){var t=p(e.components);return r.createElement(l.Provider,{value:t},e.children)},d="mdxType",f={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},m=r.forwardRef((function(e,t){var i=e.components,a=e.mdxType,n=e.originalType,l=e.parentName,s=c(e,["components","mdxType","originalType","parentName"]),d=p(i),m=a,u=d["".concat(l,".").concat(m)]||d[m]||f[m]||n;return i?r.createElement(u,o(o({ref:t},s),{},{components:i})):r.createElement(u,o({ref:t},s))}));function u(e,t){var i=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var n=i.length,o=new Array(n);o[0]=m;var c={};for(var l in t)hasOwnProperty.call(t,l)&&(c[l]=t[l]);c.originalType=e,c[d]="string"==typeof e?e:a,o[1]=c;for(var p=2;p<n;p++)o[p]=i[p];return r.createElement.apply(null,o)}return r.createElement.apply(null,i)}m.displayName="MDXCreateElement"},6505:(e,t,i)=>{i.r(t),i.d(t,{assets:()=>l,contentTitle:()=>o,default:()=>d,frontMatter:()=>n,metadata:()=>c,toc:()=>p});var r=i(7462),a=(i(7294),i(3905));const n={id:"afc",title:"afc",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"afc",description:"FileSystem commands",last_update:{date:new Date("2022-11-30T19:14:58.000Z"),author:"blacktop"}},o=void 0,c={unversionedId:"cli/ipsw/idev/afc/afc",id:"cli/ipsw/idev/afc/afc",title:"afc",description:"FileSystem commands",source:"@site/docs/cli/ipsw/idev/afc/afc.md",sourceDirName:"cli/ipsw/idev/afc",slug:"/cli/ipsw/idev/afc/",permalink:"/ipsw/docs/cli/ipsw/idev/afc/",draft:!1,editUrl:"https://github.com/blacktop/ipsw/tree/master/www/docs/cli/ipsw/idev/afc/afc.md",tags:[],version:"current",frontMatter:{id:"afc",title:"afc",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"afc",description:"FileSystem commands",last_update:{date:"2022-11-30T19:14:58.000Z",author:"blacktop"}},sidebar:"cli",previous:{title:"idev",permalink:"/ipsw/docs/cli/ipsw/idev/"},next:{title:"cat",permalink:"/ipsw/docs/cli/ipsw/idev/afc/cat"}},l={},p=[{value:"ipsw idev afc",id:"ipsw-idev-afc",level:2},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3}],s={toc:p};function d(e){let{components:t,...i}=e;return(0,a.kt)("wrapper",(0,r.Z)({},s,i,{components:t,mdxType:"MDXLayout"}),(0,a.kt)("h2",{id:"ipsw-idev-afc"},"ipsw idev afc"),(0,a.kt)("p",null,"FileSystem commands"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre"},"ipsw idev afc [flags]\n")),(0,a.kt)("h3",{id:"options"},"Options"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre"},"  -h, --help   help for afc\n")),(0,a.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre"},"      --color           colorize output\n      --config string   config file (default is $HOME/.ipsw.yaml)\n  -u, --udid string     Device UniqueDeviceID to connect to\n  -V, --verbose         verbose output\n")),(0,a.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,a.kt)("ul",null,(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/idev"},"ipsw idev"),"\t - USB connected device commands"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/idev/afc/cat"},"ipsw idev afc cat"),"\t - cat file rooted at /var/mobile/Media"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/idev/afc/ls"},"ipsw idev afc ls"),"\t - List files|dirs rooted at /var/mobile/Media"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/idev/afc/mkdir"},"ipsw idev afc mkdir"),"\t - make directory rooted at /var/mobile/Media"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/idev/afc/pull"},"ipsw idev afc pull"),"\t - Pull remote file rooted at /var/mobile/Media"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/idev/afc/push"},"ipsw idev afc push"),"\t - Push local file rooted at /var/mobile/Media"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/idev/afc/rm"},"ipsw idev afc rm"),"\t - rm file rooted at /var/mobile/Media"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/idev/afc/tree"},"ipsw idev afc tree"),"\t - List contents of directories in a tree-like format rooted at /var/mobile/Media")))}d.isMDXComponent=!0}}]);