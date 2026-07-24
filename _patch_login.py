import io

with open('/workspaces/freed/main.py', 'r', encoding='utf-8') as f:
    data = f.read()

start = data.find('LOGIN_HTML = r"""')
end_marker = 'DASHBOARD_HTML = r"""'
end = data.find(end_marker)

# The LOGIN block runs from `start` up to the end of its closing triple-quote,
# i.e. up to the position right before DASHBOARD_HTML begins.
# Closing is: '</html>"""\n\n'  -> find that right before end_marker
closing_idx = data.rfind('</html>"""', start, end) + len('</html>"""')

NEW_LOGIN = r'''LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AMIR VPN</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
<style>
@property --angle{syntax:'<angle>';initial-value:0deg;inherits:false}
*{margin:0;padding:0;box-sizing:border-box}
:root{--primary:#ff1a1a;--glow:rgba(255,26,26,0.2)}
html[data-theme="dark"]{--bg:#e4eaf6;--card:rgba(255,255,255,0.55);--card-b:rgba(0,0,0,0.06);--inp:rgba(255,255,255,0.6);--t:#1a1a2e;--ts:#666;--tt:#aaa;--primary:#1a8cff;--glow:rgba(26,140,255,0.28);--glow2:rgba(26,140,255,0.12)}
html[data-theme="light"]{--bg:#e4eaf6;--card:rgba(255,255,255,0.6);--card-b:rgba(0,0,0,0.06);--inp:rgba(255,255,255,0.65);--t:#1a1a2e;--ts:#666;--tt:#aaa;--primary:#1a8cff;--glow:rgba(26,140,255,0.28);--glow2:rgba(26,140,255,0.12)}
html[data-theme="purple"]{--bg:#0c0818;--card:rgba(168,85,247,0.06);--card-b:rgba(168,85,247,0.1);--inp:rgba(168,85,247,0.08);--t:#f0f0f0;--ts:rgba(255,255,255,0.55);--tt:rgba(255,255,255,0.2);--primary:#a855f7;--glow:rgba(168,85,247,0.32);--glow2:rgba(168,85,247,0.14)}
body{font-family:'Inter',-apple-system,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--t);transition:background .5s,color .5s;overflow:hidden}
body[dir="rtl"]{direction:rtl;text-align:right}

/* ---- drifting blurred aura blobs (motion-blur glow) ---- */
.auras{position:fixed;inset:0;z-index:0;pointer-events:none;filter:blur(60px);overflow:hidden}
.aura{position:absolute;border-radius:50%;opacity:.55;mix-blend-mode:screen;animation:drift 18s ease-in-out infinite}
.aura.a1{width:46vmax;height:46vmax;left:-10vmax;top:-12vmax;background:radial-gradient(circle,var(--glow) 0%,transparent 70%);animation-duration:22s}
.aura.a2{width:40vmax;height:40vmax;right:-12vmax;bottom:-14vmax;background:radial-gradient(circle,var(--primary) 0%,transparent 70%);opacity:.4;animation-duration:26s;animation-direction:reverse}
.aura.a3{width:30vmax;height:30vmax;left:40vmax;top:30vmax;background:radial-gradient(circle,var(--glow2) 0%,transparent 70%);animation-duration:30s}
@keyframes drift{0%,100%{transform:translate(0,0) scale(1)}33%{transform:translate(6vmax,4vmax) scale(1.15)}66%{transform:translate(-4vmax,6vmax) scale(.9)}}

.wrp{position:relative;z-index:2;width:100%;max-width:390px;padding:20px}
.box{position:relative;background:var(--card);border:1px solid var(--card-b);border-radius:28px;padding:46px 34px 30px;backdrop-filter:blur(60px) saturate(170%);-webkit-backdrop-filter:blur(60px) saturate(170%);box-shadow:0 30px 90px rgba(0,0,0,0.32),0 0 60px var(--glow),0 0 120px var(--glow),inset 0 1px 0 rgba(255,255,255,0.25);animation:boxIn 1s cubic-bezier(.16,1,.3,1) forwards;opacity:0;transform:translateY(40px) scale(.94);filter:blur(18px)}
@keyframes boxIn{60%{filter:blur(4px)}to{opacity:1;transform:none;filter:blur(0)}}
/* rotating glowing conic ring behind the glass */
.box::before{content:'';position:absolute;inset:-2px;border-radius:30px;z-index:-1;background:conic-gradient(from var(--angle),transparent 0%,var(--primary) 18%,transparent 38%,transparent 62%,var(--primary) 82%,transparent 100%);filter:blur(16px);opacity:.85;animation:spin 6s linear infinite}
@keyframes spin{to{--angle:360deg}}
/* thin animated top hairline */
.box::after{content:'';position:absolute;top:0;left:26px;right:26px;height:1px;background:linear-gradient(90deg,transparent,var(--primary) 50%,transparent);animation:lineGlow 5s ease-in-out infinite}
@keyframes lineGlow{0%,100%{opacity:.4;transform:scaleX(.4)}50%{opacity:1;transform:none}}

.logo{text-align:center;margin-bottom:26px;position:relative}
.logo .sq{width:92px;height:92px;border-radius:24px;background:linear-gradient(135deg,var(--primary),color-mix(in srgb,var(--primary),#000 45%));display:inline-flex;align-items:center;justify-content:center;margin-bottom:14px;position:relative;box-shadow:0 14px 44px var(--glow),0 0 80px var(--glow);animation:pulse 4s ease-in-out infinite}
@keyframes pulse{0%,100%{box-shadow:0 14px 44px var(--glow),0 0 60px var(--glow)}50%{box-shadow:0 18px 64px var(--glow),0 0 110px var(--glow)}}
.logo .sq svg{width:46px;height:46px;filter:drop-shadow(0 2px 6px rgba(0,0,0,.3))}
.logo .sq::after{content:'';position:absolute;inset:0;border-radius:24px;background:linear-gradient(135deg,rgba(255,255,255,0.28),transparent 60%);pointer-events:none}
.logo .nm{font-size:19px;font-weight:900;letter-spacing:-.02em;animation:slIn .6s .25s both}
.logo .sub{font-size:9px;color:var(--tt);font-weight:800;text-transform:uppercase;letter-spacing:.24em;margin-top:5px;animation:slIn .6s .35s both}
@keyframes slIn{from{opacity:0;transform:translateY(8px);filter:blur(6px)}to{opacity:1;transform:none;filter:blur(0)}}

.fg{margin-bottom:16px;animation:slIn .6s .42s both;position:relative}
.fg label{display:block;font-size:9px;font-weight:800;color:var(--ts);margin-bottom:6px;text-transform:uppercase;letter-spacing:.12em;transition:color .3s}
.fg input{width:100%;padding:12px 15px;background:var(--inp);border:1px solid var(--card-b);border-radius:14px;color:var(--t);font-size:13px;font-family:inherit;outline:none;transition:border-color .3s,box-shadow .3s;backdrop-filter:blur(10px)}
.fg input:focus{border-color:var(--primary);box-shadow:0 0 0 4px var(--glow),0 0 30px var(--glow)}
.fg input::placeholder{color:var(--tt)}
.fg:focus-within label{color:var(--primary)}

.go{width:100%;padding:12px;margin-top:4px;background:linear-gradient(135deg,var(--primary),color-mix(in srgb,var(--primary),#000 30%));border:none;border-radius:14px;color:#fff;font-size:13px;font-weight:800;font-family:inherit;cursor:pointer;transition:filter .3s,transform .2s,box-shadow .3s;letter-spacing:.04em;animation:slIn .6s .5s both;position:relative;overflow:hidden;box-shadow:0 10px 30px var(--glow)}
.go::before{content:'';position:absolute;top:0;left:-60%;width:50%;height:100%;background:linear-gradient(90deg,transparent,rgba(255,255,255,.45),transparent);transform:skewX(-20deg);transition:left .6s}
.go:hover{filter:brightness(1.12);transform:translateY(-2px);box-shadow:0 14px 40px var(--glow),0 0 60px var(--glow)}
.go:hover::before{left:130%}
.go:active{transform:translateY(0) scale(.97)}

.err{background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.18);color:#ef4444;padding:10px 13px;border-radius:12px;font-size:11px;display:none;margin-bottom:16px;text-align:center;font-weight:600;animation:shk .4s,blurIn .4s}
.err.show{display:block}
@keyframes shk{0%,100%{transform:translateX(0)}25%{transform:translateX(-4px)}75%{transform:translateX(4px)}}
@keyframes blurIn{from{filter:blur(8px);opacity:0}to{filter:blur(0);opacity:1}}

.secure{display:flex;align-items:center;justify-content:center;gap:6px;margin-top:18px;font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--ts);animation:slIn .6s .6s both}
.secure .dot{width:7px;height:7px;border-radius:50%;background:var(--green,#00b864);box-shadow:0 0 8px var(--green,#00b864);animation:live 1.6s ease-in-out infinite}
@keyframes live{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.4;transform:scale(.7)}}

.toolbar{position:fixed;top:16px;right:16px;display:flex;gap:6px;z-index:10}
.toolbar button{width:34px;height:34px;border-radius:9px;border:1px solid var(--card-b);background:var(--card);color:var(--ts);cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .2s;backdrop-filter:blur(14px)}
.toolbar button:hover{border-color:var(--primary);color:var(--primary);box-shadow:0 0 14px var(--glow)}

.theme-bar{position:fixed;top:16px;left:16px;display:flex;gap:5px;z-index:10;background:var(--card);border:1px solid var(--card-b);border-radius:11px;padding:6px;backdrop-filter:blur(30px);-webkit-backdrop-filter:blur(30px);box-shadow:0 4px 24px rgba(0,0,0,0.18)}
.theme-btn{width:22px;height:22px;border-radius:6px;cursor:pointer;border:2px solid transparent;transition:all .2s}
.theme-btn:hover{transform:scale(1.15)}
.theme-btn.on{border-color:rgba(255,255,255,.8);box-shadow:0 0 12px var(--glow)}
.tb-r{background:#ff1a1a}.tb-g{background:#00ff88}.tb-p{background:#a855f7}

canvas#galaxy{position:fixed;inset:0;z-index:1;pointer-events:none;opacity:.7}
</style>
</head>
<body>
<div class="auras"><div class="aura a1"></div><div class="aura a2"></div><div class="aura a3"></div></div>
<canvas id="galaxy"></canvas>
<div class="theme-bar">
  <div class="theme-btn tb-r on" onclick="setTheme('dark')" title="Red Neon"></div>
  <div class="theme-btn tb-g" onclick="setTheme('light')" title="Light"></div>
  <div class="theme-btn tb-p" onclick="setTheme('purple')" title="Purple Neon"></div>
</div>
<div class="toolbar">
  <button id="lang-btn" onclick="cycleLang()">EN</button>
</div>
<div class="wrp">
  <div class="box" id="box">
    <div class="logo">
      <div class="sq">
        <svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="1.8" stroke-linecap="round">
          <path d="M12 2L2 7l10 5 10-5-10-5z"/>
          <path d="M2 17l10 5 10-5"/>
          <path d="M2 12l10 5 10-5"/>
          <circle cx="12" cy="12" r="2.5" fill="#fff" opacity=".9">
            <animate attributeName="r" values="2.5;3.2;2.5" dur="2.5s" repeatCount="indefinite"/>
          </circle>
        </svg>
      </div>
      <div class="nm">AMIR VPN</div>
      <div class="sub">Secure Connection</div>
    </div>
    <div class="err" id="err"></div>
    <form id="login-form">
      <div class="fg">
        <label data-en="Password" data-fa="&#x0631;&#x0645;&#x0632; &#x0639;&#x0628;&#x0648;&#x0631;">Password</label>
        <input type="password" id="password" placeholder="&#x062A;&#x0648;&#x06CC; &#x0631;&#x0645;&#x0632;&#x0639;&#x0628;&#x0648;&#x0631;" autofocus>
      </div>
      <button type="submit" class="go" data-en="Sign In" data-fa="&#x0648;&#x0631;&#x0648;&#x062F;">Sign In</button>
    </form>
    <div class="secure"><span class="dot"></span> Encrypted Session</div>
  </div>
</div>
<script>
let lang=localStorage.getItem('amir_lang')||'en';
let theme=localStorage.getItem('amir_theme')||'dark';
function setLang(l){lang=l;document.body.dir=l==='fa'?'rtl':'ltr';document.querySelectorAll('[data-en]').forEach(el=>{const v=el.getAttribute('data-'+l);if(v)el.textContent=v});document.getElementById('lang-btn').textContent=l.toUpperCase();localStorage.setItem('amir_lang',l)}
function cycleLang(){setLang(lang==='en'?'fa':'en')}
function setTheme(t){theme=t;document.documentElement.setAttribute('data-theme',t);localStorage.setItem('amir_theme',t);document.querySelectorAll('.theme-btn').forEach(b=>b.classList.remove('on'));if(t==='dark')document.querySelector('.tb-r').classList.add('on');if(t==='light')document.querySelector('.tb-g').classList.add('on');if(t==='purple')document.querySelector('.tb-p').classList.add('on')}
setTheme(theme);setLang(lang);

document.getElementById('login-form').addEventListener('submit',async e=>{
  e.preventDefault();const err=document.getElementById('err');err.classList.remove('show');
  try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('password').value})});if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.detail||'Failed');}location.href='/dashboard';}catch(e){err.textContent=e.message;err.classList.add('show')}
});

// Galaxy field with glow + twinkle
const c=document.getElementById('galaxy'),cx=c.getContext('2d');let S=[];
function resize(){c.width=innerWidth;c.height=innerHeight}
function init(){S=[];for(let i=0;i<170;i++)S.push({x:Math.random()*c.width,y:Math.random()*c.height,r:Math.random()*1.4+.3,s:Math.random()*.25+.05,p:Math.random()*Math.PI*2})}
function draw(){cx.clearRect(0,0,c.width,c.height);const t=Date.now()*.001;S.forEach(s=>{const a=.12+.3*Math.sin(t*s.s+s.p);cx.beginPath();cx.arc(s.x,s.y,s.r,0,Math.PI*2);cx.fillStyle='rgba(255,255,255,'+a.toFixed(3)+')';cx.shadowBlur=6;cx.shadowColor='rgba(255,255,255,.8)';cx.fill()});requestAnimationFrame(draw)}
resize();init();draw();onresize=()=>{resize();init()};
</script>
</body>
</html>"""'''

new_block = NEW_LOGIN

# Reconstruct file
new_data = data[:start] + new_block + data[closing_idx:]

# Sanity checks
assert 'LOGIN_HTML = r"""' in new_data
assert new_data.count('LOGIN_HTML = r"""') == 1
assert 'DASHBOARD_HTML = r"""' in new_data
assert new_data.find('LOGIN_HTML') < new_data.find('DASHBOARD_HTML')

with open('/workspaces/freed/main.py', 'w', encoding='utf-8') as f:
    f.write(new_data)
print("WROTE OK; login block length:", len(new_block))
