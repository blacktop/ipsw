"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[0],{3905:(e,t,s)=>{s.d(t,{Zo:()=>c,kt:()=>m});var r=s(7294);function n(e,t,s){return t in e?Object.defineProperty(e,t,{value:s,enumerable:!0,configurable:!0,writable:!0}):e[t]=s,e}function i(e,t){var s=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),s.push.apply(s,r)}return s}function a(e){for(var t=1;t<arguments.length;t++){var s=null!=arguments[t]?arguments[t]:{};t%2?i(Object(s),!0).forEach((function(t){n(e,t,s[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(s)):i(Object(s)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(s,t))}))}return e}function d(e,t){if(null==e)return{};var s,r,n=function(e,t){if(null==e)return{};var s,r,n={},i=Object.keys(e);for(r=0;r<i.length;r++)s=i[r],t.indexOf(s)>=0||(n[s]=e[s]);return n}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(r=0;r<i.length;r++)s=i[r],t.indexOf(s)>=0||Object.prototype.propertyIsEnumerable.call(e,s)&&(n[s]=e[s])}return n}var l=r.createContext({}),o=function(e){var t=r.useContext(l),s=t;return e&&(s="function"==typeof e?e(t):a(a({},t),e)),s},c=function(e){var t=o(e.components);return r.createElement(l.Provider,{value:t},e.children)},p={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},u=r.forwardRef((function(e,t){var s=e.components,n=e.mdxType,i=e.originalType,l=e.parentName,c=d(e,["components","mdxType","originalType","parentName"]),u=o(s),m=n,y=u["".concat(l,".").concat(m)]||u[m]||p[m]||i;return s?r.createElement(y,a(a({ref:t},c),{},{components:s})):r.createElement(y,a({ref:t},c))}));function m(e,t){var s=arguments,n=t&&t.mdxType;if("string"==typeof e||n){var i=s.length,a=new Array(i);a[0]=u;var d={};for(var l in t)hasOwnProperty.call(t,l)&&(d[l]=t[l]);d.originalType=e,d.mdxType="string"==typeof e?e:n,a[1]=d;for(var o=2;o<i;o++)a[o]=s[o];return r.createElement.apply(null,a)}return r.createElement.apply(null,s)}u.displayName="MDXCreateElement"},9883:(e,t,s)=>{s.r(t),s.d(t,{assets:()=>l,contentTitle:()=>a,default:()=>p,frontMatter:()=>i,metadata:()=>d,toc:()=>o});var r=s(7462),n=(s(7294),s(3905));const i={id:"disass",title:"disass",hide_title:!0,sidebar_label:"disass",description:"Disassemble dyld_shared_cache at symbol/vaddr",last_update:{date:new Date("2022-11-24T20:58:11.000Z"),author:"blacktop"}},a=void 0,d={unversionedId:"cli/ipsw/dyld/disass",id:"cli/ipsw/dyld/disass",title:"disass",description:"Disassemble dyld_shared_cache at symbol/vaddr",source:"@site/docs/cli/ipsw/dyld/disass.md",sourceDirName:"cli/ipsw/dyld",slug:"/cli/ipsw/dyld/disass",permalink:"/docs/cli/ipsw/dyld/disass",draft:!1,editUrl:"https://github.com/blacktop/ipsw/tree/master/www/docs/cli/ipsw/dyld/disass.md",tags:[],version:"current",frontMatter:{id:"disass",title:"disass",hide_title:!0,sidebar_label:"disass",description:"Disassemble dyld_shared_cache at symbol/vaddr",last_update:{date:"2022-11-24T20:58:11.000Z",author:"blacktop"}},sidebar:"cli",previous:{title:"a2s",permalink:"/docs/cli/ipsw/dyld/a2s"},next:{title:"dump",permalink:"/docs/cli/ipsw/dyld/dump"}},l={},o=[{value:"ipsw dyld disass",id:"ipsw-dyld-disass",level:2},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3}],c={toc:o};function p(e){let{components:t,...s}=e;return(0,n.kt)("wrapper",(0,r.Z)({},c,s,{components:t,mdxType:"MDXLayout"}),(0,n.kt)("h2",{id:"ipsw-dyld-disass"},"ipsw dyld disass"),(0,n.kt)("p",null,"Disassemble dyld_shared_cache at symbol/vaddr"),(0,n.kt)("pre",null,(0,n.kt)("code",{parentName:"pre"},"ipsw dyld disass <dyld_shared_cache> [flags]\n")),(0,n.kt)("h3",{id:"options"},"Options"),(0,n.kt)("pre",null,(0,n.kt)("code",{parentName:"pre"},"      --cache string    Path to .a2s addr to sym cache file (speeds up analysis)\n  -c, --count uint      Number of instructions to disassemble\n  -d, --demangle        Demangle symbol names\n  -h, --help            help for disass\n  -i, --image string    dylib image to search\n      --input string    Input function JSON file\n  -j, --json            Output as JSON\n  -q, --quiet           Do NOT markup analysis (Faster)\n  -s, --symbol string   Function to disassemble\n  -a, --vaddr uint      Virtual address to start disassembling\n")),(0,n.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,n.kt)("pre",null,(0,n.kt)("code",{parentName:"pre"},"      --color           colorize output\n      --config string   config file (default is $HOME/.ipsw.yaml)\n  -V, --verbose         verbose output\n")),(0,n.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,n.kt)("ul",null,(0,n.kt)("li",{parentName:"ul"},(0,n.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/dyld"},"ipsw dyld"),"\t - Parse dyld_shared_cache")))}p.isMDXComponent=!0}}]);