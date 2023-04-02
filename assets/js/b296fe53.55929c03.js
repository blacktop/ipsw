"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[8224],{3905:(e,o,t)=>{t.d(o,{Zo:()=>p,kt:()=>u});var n=t(7294);function r(e,o,t){return o in e?Object.defineProperty(e,o,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[o]=t,e}function a(e,o){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);o&&(n=n.filter((function(o){return Object.getOwnPropertyDescriptor(e,o).enumerable}))),t.push.apply(t,n)}return t}function i(e){for(var o=1;o<arguments.length;o++){var t=null!=arguments[o]?arguments[o]:{};o%2?a(Object(t),!0).forEach((function(o){r(e,o,t[o])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):a(Object(t)).forEach((function(o){Object.defineProperty(e,o,Object.getOwnPropertyDescriptor(t,o))}))}return e}function l(e,o){if(null==e)return{};var t,n,r=function(e,o){if(null==e)return{};var t,n,r={},a=Object.keys(e);for(n=0;n<a.length;n++)t=a[n],o.indexOf(t)>=0||(r[t]=e[t]);return r}(e,o);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);for(n=0;n<a.length;n++)t=a[n],o.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(r[t]=e[t])}return r}var d=n.createContext({}),s=function(e){var o=n.useContext(d),t=o;return e&&(t="function"==typeof e?e(o):i(i({},o),e)),t},p=function(e){var o=s(e.components);return n.createElement(d.Provider,{value:o},e.children)},c="mdxType",w={inlineCode:"code",wrapper:function(e){var o=e.children;return n.createElement(n.Fragment,{},o)}},m=n.forwardRef((function(e,o){var t=e.components,r=e.mdxType,a=e.originalType,d=e.parentName,p=l(e,["components","mdxType","originalType","parentName"]),c=s(t),m=r,u=c["".concat(d,".").concat(m)]||c[m]||w[m]||a;return t?n.createElement(u,i(i({ref:o},p),{},{components:t})):n.createElement(u,i({ref:o},p))}));function u(e,o){var t=arguments,r=o&&o.mdxType;if("string"==typeof e||r){var a=t.length,i=new Array(a);i[0]=m;var l={};for(var d in o)hasOwnProperty.call(o,d)&&(l[d]=o[d]);l.originalType=e,l[c]="string"==typeof e?e:r,i[1]=l;for(var s=2;s<a;s++)i[s]=t[s];return n.createElement.apply(null,i)}return n.createElement.apply(null,t)}m.displayName="MDXCreateElement"},9350:(e,o,t)=>{t.r(o),t.d(o,{assets:()=>d,contentTitle:()=>i,default:()=>w,frontMatter:()=>a,metadata:()=>l,toc:()=>s});var n=t(7462),r=(t(7294),t(3905));const a={id:"download",title:"download",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"download",description:"Download Apple Firmware files (and more)"},i=void 0,l={unversionedId:"cli/ipsw/download/download",id:"cli/ipsw/download/download",title:"download",description:"Download Apple Firmware files (and more)",source:"@site/docs/cli/ipsw/download/download.md",sourceDirName:"cli/ipsw/download",slug:"/cli/ipsw/download/",permalink:"/ipsw/docs/cli/ipsw/download/",draft:!1,editUrl:"https://github.com/blacktop/ipsw/tree/master/www/docs/cli/ipsw/download/download.md",tags:[],version:"current",frontMatter:{id:"download",title:"download",hide_title:!0,hide_table_of_contents:!0,sidebar_label:"download",description:"Download Apple Firmware files (and more)"},sidebar:"cli",previous:{title:"diff",permalink:"/ipsw/docs/cli/ipsw/diff"},next:{title:"dev",permalink:"/ipsw/docs/cli/ipsw/download/dev"}},d={},s=[{value:"ipsw download",id:"ipsw-download",level:2},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3}],p={toc:s},c="wrapper";function w(e){let{components:o,...t}=e;return(0,r.kt)(c,(0,n.Z)({},p,t,{components:o,mdxType:"MDXLayout"}),(0,r.kt)("h2",{id:"ipsw-download"},"ipsw download"),(0,r.kt)("p",null,"Download Apple Firmware files (and more)"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre"},"ipsw download [flags]\n")),(0,r.kt)("h3",{id:"options"},"Options"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre"},"      --black-list stringArray   iOS device black list\n  -b, --build string             iOS BuildID (i.e. 16F203)\n  -y, --confirm                  do not prompt user for confirmation\n  -d, --device string            iOS Device (i.e. iPhone11,2)\n  -h, --help                     help for download\n      --insecure                 do not verify ssl certs\n  -m, --model string             iOS Model (i.e. D321AP)\n      --proxy string             HTTP/HTTPS proxy\n  -_, --remove-commas            replace commas in IPSW filename with underscores\n      --restart-all              always restart resumable IPSWs\n      --resume-all               always resume resumable IPSWs\n      --skip-all                 always skip resumable IPSWs\n  -v, --version string           iOS Version (i.e. 12.3.1)\n      --white-list stringArray   iOS device white list\n")),(0,r.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre"},"      --color           colorize output\n      --config string   config file (default is $HOME/.ipsw/config.yaml)\n  -V, --verbose         verbose output\n")),(0,r.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("a",{parentName:"li",href:"/docs/cli/ipsw"},"ipsw"),"\t - Download and Parse IPSWs (and SO much more)"),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/download/dev"},"ipsw download dev"),"\t - Download IPSWs (and more) from ",(0,r.kt)("a",{parentName:"li",href:"https://developer.apple.com/download"},"https://developer.apple.com/download")),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/download/git"},"ipsw download git"),"\t - Download github.com/orgs/apple-oss-distributions tarballs"),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/download/ipa"},"ipsw download ipa"),"\t - Download App Packages from the iOS App Store"),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/download/ipsw"},"ipsw download ipsw"),"\t - Download and parse IPSW(s) from the internets"),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/download/macos"},"ipsw download macos"),"\t - Download macOS installers"),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/download/ota"},"ipsw download ota"),"\t - Download OTAs"),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/download/rss"},"ipsw download rss"),"\t - Read Releases - Apple Developer RSS Feed"),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/download/tss"},"ipsw download tss"),"\t - \ud83d\udea7 Download SHSH Blobs"),(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/download/wiki"},"ipsw download wiki"),"\t - Download old(er) IPSWs from theiphonewiki.com")))}w.isMDXComponent=!0}}]);