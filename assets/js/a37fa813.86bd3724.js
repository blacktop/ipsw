"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[9818],{3905:(e,t,i)=>{i.d(t,{Zo:()=>c,kt:()=>u});var r=i(7294);function a(e,t,i){return t in e?Object.defineProperty(e,t,{value:i,enumerable:!0,configurable:!0,writable:!0}):e[t]=i,e}function n(e,t){var i=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),i.push.apply(i,r)}return i}function l(e){for(var t=1;t<arguments.length;t++){var i=null!=arguments[t]?arguments[t]:{};t%2?n(Object(i),!0).forEach((function(t){a(e,t,i[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(i)):n(Object(i)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(i,t))}))}return e}function s(e,t){if(null==e)return{};var i,r,a=function(e,t){if(null==e)return{};var i,r,a={},n=Object.keys(e);for(r=0;r<n.length;r++)i=n[r],t.indexOf(i)>=0||(a[i]=e[i]);return a}(e,t);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);for(r=0;r<n.length;r++)i=n[r],t.indexOf(i)>=0||Object.prototype.propertyIsEnumerable.call(e,i)&&(a[i]=e[i])}return a}var o=r.createContext({}),p=function(e){var t=r.useContext(o),i=t;return e&&(i="function"==typeof e?e(t):l(l({},t),e)),i},c=function(e){var t=p(e.components);return r.createElement(o.Provider,{value:t},e.children)},d={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},m=r.forwardRef((function(e,t){var i=e.components,a=e.mdxType,n=e.originalType,o=e.parentName,c=s(e,["components","mdxType","originalType","parentName"]),m=p(i),u=a,w=m["".concat(o,".").concat(u)]||m[u]||d[u]||n;return i?r.createElement(w,l(l({ref:t},c),{},{components:i})):r.createElement(w,l({ref:t},c))}));function u(e,t){var i=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var n=i.length,l=new Array(n);l[0]=m;var s={};for(var o in t)hasOwnProperty.call(t,o)&&(s[o]=t[o]);s.originalType=e,s.mdxType="string"==typeof e?e:a,l[1]=s;for(var p=2;p<n;p++)l[p]=i[p];return r.createElement.apply(null,l)}return r.createElement.apply(null,i)}m.displayName="MDXCreateElement"},7179:(e,t,i)=>{i.r(t),i.d(t,{assets:()=>o,contentTitle:()=>l,default:()=>d,frontMatter:()=>n,metadata:()=>s,toc:()=>p});var r=i(7462),a=(i(7294),i(3905));const n={id:"ipsw",title:"ipsw",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"ipsw",description:"Download and Parse IPSWs (and SO much more)",last_update:{date:new Date("2022-11-26T01:20:31.000Z"),author:"blacktop"}},l=void 0,s={unversionedId:"cli/ipsw/ipsw",id:"cli/ipsw/ipsw",title:"ipsw",description:"Download and Parse IPSWs (and SO much more)",source:"@site/docs/cli/ipsw/ipsw.md",sourceDirName:"cli/ipsw",slug:"/cli/ipsw/",permalink:"/ipsw/docs/cli/ipsw/",draft:!1,editUrl:"https://github.com/blacktop/ipsw/tree/master/www/docs/cli/ipsw/ipsw.md",tags:[],version:"current",frontMatter:{id:"ipsw",title:"ipsw",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"ipsw",description:"Download and Parse IPSWs (and SO much more)",last_update:{date:"2022-11-26T01:20:31.000Z",author:"blacktop"}},sidebar:"cli",next:{title:"device-list",permalink:"/ipsw/docs/cli/ipsw/device-list"}},o={},p=[{value:"ipsw",id:"ipsw",level:2},{value:"Options",id:"options",level:3},{value:"SEE ALSO",id:"see-also",level:3}],c={toc:p};function d(e){let{components:t,...i}=e;return(0,a.kt)("wrapper",(0,r.Z)({},c,i,{components:t,mdxType:"MDXLayout"}),(0,a.kt)("h2",{id:"ipsw"},"ipsw"),(0,a.kt)("p",null,"Download and Parse IPSWs (and SO much more)"),(0,a.kt)("h3",{id:"options"},"Options"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre"},"      --color           colorize output\n      --config string   config file (default is $HOME/.ipsw.yaml)\n  -h, --help            help for ipsw\n  -V, --verbose         verbose output\n")),(0,a.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,a.kt)("ul",null,(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/device-list"},"ipsw device-list"),"\t - List all iOS devices"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/download"},"ipsw download"),"\t - Download Apple Firmware files (and more)"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/dtree"},"ipsw dtree"),"\t - Parse DeviceTree"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/dyld"},"ipsw dyld"),"\t - Parse dyld_shared_cache"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/ent"},"ipsw ent"),"\t - Search IPSW filesystem DMG for MachOs with a given entitlement"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/extract"},"ipsw extract"),"\t - Extract kernelcache, dyld_shared_cache or DeviceTree from IPSW/OTA"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/iboot"},"ipsw iboot"),"\t - Dump firmwares"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/idev"},"ipsw idev"),"\t - USB connected device commands"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/img4"},"ipsw img4"),"\t - Parse Img4"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/info"},"ipsw info"),"\t - Display IPSW/OTA Info"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/kernel"},"ipsw kernel"),"\t - Parse kernelcache"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/macho"},"ipsw macho"),"\t - Parse MachO"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/mdevs"},"ipsw mdevs"),"\t - List all MobileDevices in IPSW"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/mount"},"ipsw mount"),"\t - Mount DMG from IPSW"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/ota"},"ipsw ota"),"\t - Parse OTAs"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/sepfw"},"ipsw sepfw"),"\t - Dump MachOs"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/shsh"},"ipsw shsh"),"\t - Get shsh blobs from device"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/symbolicate"},"ipsw symbolicate"),"\t - Symbolicate ARM 64-bit crash logs (similar to Apple's symbolicatecrash)"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/update"},"ipsw update"),"\t - Download an ipsw update if one exists"),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/version"},"ipsw version"),"\t - Print the version number of ipsw")))}d.isMDXComponent=!0}}]);