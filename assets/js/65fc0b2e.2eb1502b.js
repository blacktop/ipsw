"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[5128],{3905:(e,t,n)=>{n.d(t,{Zo:()=>p,kt:()=>m});var r=n(7294);function i(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function o(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function a(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?o(Object(n),!0).forEach((function(t){i(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):o(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function c(e,t){if(null==e)return{};var n,r,i=function(e,t){if(null==e)return{};var n,r,i={},o=Object.keys(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||(i[n]=e[n]);return i}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(i[n]=e[n])}return i}var l=r.createContext({}),s=function(e){var t=r.useContext(l),n=t;return e&&(n="function"==typeof e?e(t):a(a({},t),e)),n},p=function(e){var t=s(e.components);return r.createElement(l.Provider,{value:t},e.children)},f={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},u=r.forwardRef((function(e,t){var n=e.components,i=e.mdxType,o=e.originalType,l=e.parentName,p=c(e,["components","mdxType","originalType","parentName"]),u=s(n),m=i,d=u["".concat(l,".").concat(m)]||u[m]||f[m]||o;return n?r.createElement(d,a(a({ref:t},p),{},{components:n})):r.createElement(d,a({ref:t},p))}));function m(e,t){var n=arguments,i=t&&t.mdxType;if("string"==typeof e||i){var o=n.length,a=new Array(o);a[0]=u;var c={};for(var l in t)hasOwnProperty.call(t,l)&&(c[l]=t[l]);c.originalType=e,c.mdxType="string"==typeof e?e:i,a[1]=c;for(var s=2;s<o;s++)a[s]=n[s];return r.createElement.apply(null,a)}return r.createElement.apply(null,n)}u.displayName="MDXCreateElement"},2749:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>l,contentTitle:()=>a,default:()=>f,frontMatter:()=>o,metadata:()=>c,toc:()=>s});var r=n(7462),i=(n(7294),n(3905));const o={id:"info",title:"info",hide_title:!0,sidebar_label:"info",description:"Explore a MachO file",last_update:{date:new Date("2022-11-24T20:58:11.000Z"),author:"blacktop"}},a=void 0,c={unversionedId:"cli/ipsw/macho/info",id:"cli/ipsw/macho/info",title:"info",description:"Explore a MachO file",source:"@site/docs/cli/ipsw/macho/info.md",sourceDirName:"cli/ipsw/macho",slug:"/cli/ipsw/macho/info",permalink:"/docs/cli/ipsw/macho/info",draft:!1,editUrl:"https://github.com/blacktop/ipsw/tree/master/www/docs/cli/ipsw/macho/info.md",tags:[],version:"current",frontMatter:{id:"info",title:"info",hide_title:!0,sidebar_label:"info",description:"Explore a MachO file",last_update:{date:"2022-11-24T20:58:11.000Z",author:"blacktop"}},sidebar:"cli",previous:{title:"dump",permalink:"/docs/cli/ipsw/macho/dump"},next:{title:"lipo",permalink:"/docs/cli/ipsw/macho/lipo"}},l={},s=[{value:"ipsw macho info",id:"ipsw-macho-info",level:2},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3}],p={toc:s};function f(e){let{components:t,...n}=e;return(0,i.kt)("wrapper",(0,r.Z)({},p,n,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("h2",{id:"ipsw-macho-info"},"ipsw macho info"),(0,i.kt)("p",null,"Explore a MachO file"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"ipsw macho info <macho> [flags]\n")),(0,i.kt)("h3",{id:"options"},"Options"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"  -z, --all-fileset-entries     Parse all fileset entries\n  -a, --arch string             Which architecture to use for fat/universal MachO\n      --dump-cert               Dump the certificate\n  -e, --ent                     Print entitlements\n  -x, --extract-fileset-entry   Extract the fileset entry\n  -t, --fileset-entry string    Which fileset entry to analyze\n  -u, --fixups                  Print fixup chains\n  -d, --header                  Print the mach header\n  -h, --help                    help for info\n  -l, --loads                   Print the load commands\n  -o, --objc                    Print ObjC info\n  -r, --objc-refs               Print ObjC references\n      --output string           Directory to extract files to\n  -s, --sig                     Print code signature\n  -f, --starts                  Print function starts\n  -c, --strings                 Print cstrings\n  -n, --symbols                 Print symbols\n")),(0,i.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre"},"      --color           colorize output\n      --config string   config file (default is $HOME/.ipsw.yaml)\n  -V, --verbose         verbose output\n")),(0,i.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/macho"},"ipsw macho"),"\t - Parse MachO")))}f.isMDXComponent=!0}}]);