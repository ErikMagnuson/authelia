import{c as m,j as t,o as y,n as P,s as B,U as M,w as h,q as n,W as S,r as p,p as g,_ as R,t as _,v as H}from"./index.2cf54ca8.js";import{S as U}from"./mui.FormControlLabel.9192796d.js";const E=m(t.jsx("path",{d:"M19 5v14H5V5h14m0-2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2z"}),"CheckBoxOutlineBlank"),O=m(t.jsx("path",{d:"M19 3H5c-1.11 0-2 .9-2 2v14c0 1.1.89 2 2 2h14c1.11 0 2-.9 2-2V5c0-1.1-.89-2-2-2zm-9 14l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"}),"CheckBox"),V=m(t.jsx("path",{d:"M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-2 10H7v-2h10v2z"}),"IndeterminateCheckBox");function L(o){return P("MuiCheckbox",o)}const N=y("MuiCheckbox",["root","checked","disabled","indeterminate","colorPrimary","colorSecondary","sizeSmall","sizeMedium"]),u=N,w=["checkedIcon","color","icon","indeterminate","indeterminateIcon","inputProps","size","className"],F=o=>{const{classes:e,indeterminate:c,color:a,size:r}=o,s={root:["root",c&&"indeterminate",`color${h(a)}`,`size${h(r)}`]},l=H(s,L,e);return n({},e,l)},W=B(U,{shouldForwardProp:o=>M(o)||o==="classes",name:"MuiCheckbox",slot:"Root",overridesResolver:(o,e)=>{const{ownerState:c}=o;return[e.root,c.indeterminate&&e.indeterminate,c.color!=="default"&&e[`color${h(c.color)}`]]}})(({theme:o,ownerState:e})=>n({color:(o.vars||o).palette.text.secondary},!e.disableRipple&&{"&:hover":{backgroundColor:o.vars?`rgba(${e.color==="default"?o.vars.palette.action.activeChannel:o.vars.palette[e.color].mainChannel} / ${o.vars.palette.action.hoverOpacity})`:S(e.color==="default"?o.palette.action.active:o.palette[e.color].main,o.palette.action.hoverOpacity),"@media (hover: none)":{backgroundColor:"transparent"}}},e.color!=="default"&&{[`&.${u.checked}, &.${u.indeterminate}`]:{color:(o.vars||o).palette[e.color].main},[`&.${u.disabled}`]:{color:(o.vars||o).palette.action.disabled}})),q=t.jsx(O,{}),T=t.jsx(E,{}),A=t.jsx(V,{}),D=p.forwardRef(function(e,c){var a,r;const s=g({props:e,name:"MuiCheckbox"}),{checkedIcon:l=q,color:f="primary",icon:I=T,indeterminate:i=!1,indeterminateIcon:x=A,inputProps:z,size:d="medium",className:$}=s,j=R(s,w),C=i?x:I,k=i?x:l,v=n({},s,{color:f,indeterminate:i,size:d}),b=F(v);return t.jsx(W,n({type:"checkbox",inputProps:n({"data-indeterminate":i},z),icon:p.cloneElement(C,{fontSize:(a=C.props.fontSize)!=null?a:d}),checkedIcon:p.cloneElement(k,{fontSize:(r=k.props.fontSize)!=null?r:d}),ownerState:v,ref:c,className:_(b.root,$)},j,{classes:b}))}),K=D;export{K as C};