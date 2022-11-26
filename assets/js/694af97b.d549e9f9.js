"use strict";(self.webpackChunkdocumentation=self.webpackChunkdocumentation||[]).push([[9795],{3905:(e,t,n)=>{n.d(t,{Zo:()=>l,kt:()=>p});var r=n(7294);function f(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function s(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function a(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?s(Object(n),!0).forEach((function(t){f(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):s(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function i(e,t){if(null==e)return{};var n,r,f=function(e,t){if(null==e)return{};var n,r,f={},s=Object.keys(e);for(r=0;r<s.length;r++)n=s[r],t.indexOf(n)>=0||(f[n]=e[n]);return f}(e,t);if(Object.getOwnPropertySymbols){var s=Object.getOwnPropertySymbols(e);for(r=0;r<s.length;r++)n=s[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(f[n]=e[n])}return f}var c=r.createContext({}),o=function(e){var t=r.useContext(c),n=t;return e&&(n="function"==typeof e?e(t):a(a({},t),e)),n},l=function(e){var t=o(e.components);return r.createElement(c.Provider,{value:t},e.children)},u={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},d=r.forwardRef((function(e,t){var n=e.components,f=e.mdxType,s=e.originalType,c=e.parentName,l=i(e,["components","mdxType","originalType","parentName"]),d=o(n),p=f,m=d["".concat(c,".").concat(p)]||d[p]||u[p]||s;return n?r.createElement(m,a(a({ref:t},l),{},{components:n})):r.createElement(m,a({ref:t},l))}));function p(e,t){var n=arguments,f=t&&t.mdxType;if("string"==typeof e||f){var s=n.length,a=new Array(s);a[0]=d;var i={};for(var c in t)hasOwnProperty.call(t,c)&&(i[c]=t[c]);i.originalType=e,i.mdxType="string"==typeof e?e:f,a[1]=i;for(var o=2;o<s;o++)a[o]=n[o];return r.createElement.apply(null,a)}return r.createElement.apply(null,n)}d.displayName="MDXCreateElement"},3993:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>c,contentTitle:()=>a,default:()=>u,frontMatter:()=>s,metadata:()=>i,toc:()=>o});var r=n(7462),f=(n(7294),n(3905));const s={hide_table_of_contents:!0},a="Dump Syscalls",i={unversionedId:"guides/dump_syscalls",id:"guides/dump_syscalls",title:"Dump Syscalls",description:"",source:"@site/docs/guides/dump_syscalls.md",sourceDirName:"guides",slug:"/guides/dump_syscalls",permalink:"/ipsw/docs/guides/dump_syscalls",draft:!1,editUrl:"https://github.com/blacktop/ipsw/tree/master/www/docs/guides/dump_syscalls.md",tags:[],version:"current",frontMatter:{hide_table_of_contents:!0},sidebar:"docs",previous:{title:"Gadget Search",permalink:"/ipsw/docs/guides/gadget_search"},next:{title:"Lookup DSC Symbols",permalink:"/ipsw/docs/guides/dump_dsc_syms"}},c={},o=[],l={toc:o};function u(e){let{components:t,...n}=e;return(0,f.kt)("wrapper",(0,r.Z)({},l,n,{components:t,mdxType:"MDXLayout"}),(0,f.kt)("h1",{id:"dump-syscalls"},"Dump Syscalls"),(0,f.kt)("pre",null,(0,f.kt)("code",{parentName:"pre",className:"language-bash"},"\u276f ipsw kernel syscall 20A5312j__iPhone14,2/kernelcache.release.iPhone14,2 | head\n0:   syscall call=0xfffffff0081f28f4 munge=0x0                ret=int      narg=0 (bytes=0)  { int nosys(void); }   { indirect syscall }\n1:   exit    call=0xfffffff0081aac70 munge=0xfffffff007ecd07c ret=none     narg=1 (bytes=4)  { void exit(int rval); }\n2:   fork    call=0xfffffff0081b265c munge=0x0                ret=int      narg=0 (bytes=0)  { int fork(void); }\n3:   read    call=0xfffffff0081f3270 munge=0xfffffff007ecd09c ret=ssize_t  narg=3 (bytes=12) { user_ssize_t read(int fd, user_addr_t cbuf, user_size_t nbyte); }\n4:   write   call=0xfffffff0081f40f8 munge=0xfffffff007ecd09c ret=ssize_t  narg=3 (bytes=12) { user_ssize_t write(int fd, user_addr_t cbuf, user_size_t nbyte); }\n5:   open    call=0xfffffff007f0bf68 munge=0xfffffff007ecd09c ret=int      narg=3 (bytes=12) { int open(user_addr_t path, int flags, int mode); }\n6:   close   call=0xfffffff00818d870 munge=0xfffffff007ecd07c ret=int      narg=1 (bytes=4)  { int sys_close(int fd); }\n7:   wait4   call=0xfffffff0081ae384 munge=0xfffffff007ecd0b8 ret=int      narg=4 (bytes=16) { int wait4(int pid, user_addr_t status, int options, user_addr_t rusage); }\n8:   enosys  call=0xfffffff0081f28d4 munge=0x0                ret=int      narg=0 (bytes=0)  { int enosys(void); }   { old creat }\n9:   link    call=0xfffffff007f0d670 munge=0xfffffff007ecd088 ret=int      narg=2 (bytes=8)  { int link(user_addr_t path, user_addr_t link); }\n")))}u.isMDXComponent=!0}}]);