"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[8116],{3905:(e,t,r)=>{r.d(t,{Zo:()=>d,kt:()=>u});var n=r(7294);function o(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function i(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function a(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?i(Object(r),!0).forEach((function(t){o(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):i(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function s(e,t){if(null==e)return{};var r,n,o=function(e,t){if(null==e)return{};var r,n,o={},i=Object.keys(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||(o[r]=e[r]);return o}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(o[r]=e[r])}return o}var l=n.createContext({}),p=function(e){var t=n.useContext(l),r=t;return e&&(r="function"==typeof e?e(t):a(a({},t),e)),r},d=function(e){var t=p(e.components);return n.createElement(l.Provider,{value:t},e.children)},c={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},w=n.forwardRef((function(e,t){var r=e.components,o=e.mdxType,i=e.originalType,l=e.parentName,d=s(e,["components","mdxType","originalType","parentName"]),w=p(r),u=o,m=w["".concat(l,".").concat(u)]||w[u]||c[u]||i;return r?n.createElement(m,a(a({ref:t},d),{},{components:r})):n.createElement(m,a({ref:t},d))}));function u(e,t){var r=arguments,o=t&&t.mdxType;if("string"==typeof e||o){var i=r.length,a=new Array(i);a[0]=w;var s={};for(var l in t)hasOwnProperty.call(t,l)&&(s[l]=t[l]);s.originalType=e,s.mdxType="string"==typeof e?e:o,a[1]=s;for(var p=2;p<i;p++)a[p]=r[p];return n.createElement.apply(null,a)}return n.createElement.apply(null,r)}w.displayName="MDXCreateElement"},2906:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>l,contentTitle:()=>a,default:()=>c,frontMatter:()=>i,metadata:()=>s,toc:()=>p});var n=r(7462),o=(r(7294),r(3905));const i={id:"ipsw",title:"ipsw",hide_title:!0,sidebar_label:"ipsw",description:"Download and parse IPSW(s) from the internets",last_update:{date:new Date("2022-11-24T20:58:11.000Z"),author:"blacktop"}},a=void 0,s={unversionedId:"cli/ipsw/download/ipsw",id:"cli/ipsw/download/ipsw",title:"ipsw",description:"Download and parse IPSW(s) from the internets",source:"@site/docs/cli/ipsw/download/ipsw.md",sourceDirName:"cli/ipsw/download",slug:"/cli/ipsw/download/ipsw",permalink:"/docs/cli/ipsw/download/ipsw",draft:!1,editUrl:"https://github.com/blacktop/ipsw/tree/master/www/docs/cli/ipsw/download/ipsw.md",tags:[],version:"current",frontMatter:{id:"ipsw",title:"ipsw",hide_title:!0,sidebar_label:"ipsw",description:"Download and parse IPSW(s) from the internets",last_update:{date:"2022-11-24T20:58:11.000Z",author:"blacktop"}},sidebar:"cli",previous:{title:"git",permalink:"/docs/cli/ipsw/download/git"},next:{title:"macos",permalink:"/docs/cli/ipsw/download/macos"}},l={},p=[{value:"ipsw download ipsw",id:"ipsw-download-ipsw",level:2},{value:"Options",id:"options",level:3},{value:"Options inherited from parent commands",id:"options-inherited-from-parent-commands",level:3},{value:"SEE ALSO",id:"see-also",level:3}],d={toc:p};function c(e){let{components:t,...r}=e;return(0,o.kt)("wrapper",(0,n.Z)({},d,r,{components:t,mdxType:"MDXLayout"}),(0,o.kt)("h2",{id:"ipsw-download-ipsw"},"ipsw download ipsw"),(0,o.kt)("p",null,"Download and parse IPSW(s) from the internets"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},"ipsw download ipsw [flags]\n")),(0,o.kt)("h3",{id:"options"},"Options"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},"      --beta                    Download Beta IPSWs\n      --dyld                    Extract dyld_shared_cache(s) from remote IPSW\n  -a, --dyld-arch stringArray   dyld_shared_cache architecture(s) to remote extract\n  -f, --flat                    Do NOT perserve directory structure when downloading with --pattern\n  -h, --help                    help for ipsw\n      --ibridge                 Download iBridge IPSWs\n      --kernel                  Extract kernelcache from remote IPSW\n      --latest                  Download latest IPSWs\n      --macos                   Download macOS IPSWs\n  -o, --output string           Folder to download files to\n      --pattern string          Download remote files that match regex\n      --show-latest             Show latest iOS version\n  -u, --usb                     Download IPSWs for USB attached iDevices\n")),(0,o.kt)("h3",{id:"options-inherited-from-parent-commands"},"Options inherited from parent commands"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},"      --black-list stringArray   iOS device black list\n  -b, --build string             iOS BuildID (i.e. 16F203)\n      --color                    colorize output\n      --config string            config file (default is $HOME/.ipsw.yaml)\n  -y, --confirm                  do not prompt user for confirmation\n  -d, --device string            iOS Device (i.e. iPhone11,2)\n      --insecure                 do not verify ssl certs\n  -m, --model string             iOS Model (i.e. D321AP)\n      --proxy string             HTTP/HTTPS proxy\n  -_, --remove-commas            replace commas in IPSW filename with underscores\n      --restart-all              always restart resumable IPSWs\n      --resume-all               always resume resumable IPSWs\n      --skip-all                 always skip resumable IPSWs\n  -V, --verbose                  verbose output\n  -v, --version string           iOS Version (i.e. 12.3.1)\n      --white-list stringArray   iOS device white list\n")),(0,o.kt)("h3",{id:"see-also"},"SEE ALSO"),(0,o.kt)("ul",null,(0,o.kt)("li",{parentName:"ul"},(0,o.kt)("a",{parentName:"li",href:"/docs/cli/ipsw/download"},"ipsw download"),"\t - Download Apple Firmware files (and more)")))}c.isMDXComponent=!0}}]);