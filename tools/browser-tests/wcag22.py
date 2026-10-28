"""Manual WCAG 2.2 checks axe cannot make: 2.4.11 focus not obscured, 2.5.8 target size,
1.4.10 reflow at 320 px, 1.4.12 text spacing. Usage: wcag22.py url..."""
import asyncio, json, sys
sys.path.insert(0, __import__('os').path.dirname(__file__))
from axe_run import B
CHECK = r"""
(async () => {
  const out = {target: [], obscured: [], clipped: []};
  const vis = e => { const r = e.getBoundingClientRect(); const s = getComputedStyle(e); return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && !e.closest('[hidden]'); };
  const sel = 'a[href],button,input:not([type=hidden]),select,textarea,[tabindex]:not([tabindex="-1"]),[role=tab],[role=button]';
  const els = [...document.querySelectorAll(sel)].filter(vis);
  const name = e => (e.tagName + (e.id ? '#' + e.id : '') + '.' + (e.className || '').toString().split(' ')[0] + ' "' + (e.textContent || e.value || e.getAttribute('aria-label') || '').trim().slice(0, 30) + '"');
  // 2.5.8: 24x24, or a 24px circle around it free of other targets (spacing exception); inline links in text are exempt.
  for (const e of els) {
    const r = e.getBoundingClientRect();
    const inline = e.tagName === 'A' && getComputedStyle(e).display === 'inline' && e.parentElement && /P|LI|SPAN|TD/.test(e.parentElement.tagName);
    if (inline) continue;
    // a native checkbox/radio inside a label: the label is the target
    const lab = (e.type === 'checkbox' || e.type === 'radio') ? e.closest('label') : null;
    const rr = lab ? lab.getBoundingClientRect() : r;
    if (rr.width >= 24 && rr.height >= 24) continue;
    if (lab && getComputedStyle(e).opacity === '0') continue;
    const cx = rr.left + rr.width / 2, cy = rr.top + rr.height / 2;
    const crowded = els.some(o => { if (o === e || o.contains(e) || e.contains(o)) return false; const q = o.getBoundingClientRect(); const dx = Math.max(q.left - cx, 0, cx - q.right), dy = Math.max(q.top - cy, 0, cy - q.bottom); return Math.hypot(dx, dy) < 12; });
    if (crowded) out.target.push(name(e) + ' ' + Math.round(rr.width) + 'x' + Math.round(rr.height));
  }
  // 2.4.11: a focused element must not be entirely hidden by sticky/fixed content.
  const sticky = [...document.querySelectorAll('body *')].filter(x => /sticky|fixed/.test(getComputedStyle(x).position) && vis(x));
  for (const e of els.slice(0, 400)) {
    if (sticky.some(s => s.contains(e))) continue;
    e.focus({preventScroll: false});
    await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)));
    if (document.activeElement !== e) continue;
    const r = e.getBoundingClientRect();
    const covered = sticky.some(s => { const q = s.getBoundingClientRect(); return r.top >= q.top && r.bottom <= q.bottom && r.left >= q.left && r.right <= q.right; });
    const off = r.bottom <= 0 || r.top >= innerHeight;
    if (covered || off) out.obscured.push(name(e));
  }
  return out;
})()
"""
REFLOW = "(()=>({w: document.documentElement.scrollWidth, v: innerWidth}))()"
SPACING = """(()=>{const s=document.createElement('style');s.textContent='*{line-height:1.5!important;letter-spacing:.12em!important;word-spacing:.16em!important}p{margin-bottom:2em!important}';document.head.appendChild(s);
 const bad=[...document.querySelectorAll('button,label,.opt-label,h1,h2,h3,p,a')].filter(e=>e.offsetParent&&getComputedStyle(e).clipPath!=='inset(50%)'&&!e.closest('.vh,.meta')&&(e.scrollWidth>e.clientWidth+1&&getComputedStyle(e).overflowX==='hidden'||e.scrollHeight>e.clientHeight+1&&getComputedStyle(e).overflowY==='hidden')).map(e=>e.tagName+' '+(e.textContent||'').trim().slice(0,30));
 s.remove(); return bad.slice(0,10);})()"""
async def main():
    found = 0
    for w,h in [(1280,900),(320,800)]:
        b=B(); await b.start(w,h)
        for url in sys.argv[1:]:
            await b.send("Page.navigate",url=url); await asyncio.sleep(1.5)
            for step in range(12):
                tabs=await b.ev("document.querySelectorAll('[role=tab]').length") or 0
                for t in range(min(max(1,tabs),3)):
                    if tabs: await b.ev(f"document.querySelectorAll('[role=tab]')[{t}].click()"); await asyncio.sleep(0.2)
                    r=await b.ev(CHECK) or {}
                    tag=f"{w}px {url.split('/')[-1][:28]} s{step} t{t}"
                    for k in ('target','obscured'):
                        for x in r.get(k,[])[:5]:
                            found += 1; print(f"{k:9} {tag}: {x}")
                    rf=await b.ev(REFLOW)
                    if w==320 and rf and rf['w']>rf['v']+1:
                        found += 1; print(f"reflow    {tag}: page {rf['w']}px wide in a {rf['v']}px window")
                    sp=await b.ev(SPACING) or []
                    for x in sp[:3]:
                        found += 1; print(f"spacing   {tag}: clipped {x}")
                moved=await b.ev("(()=>{const n=[...document.querySelectorAll('button,a')].find(e=>/^\\s*Next/.test(e.textContent)&&!e.disabled&&e.offsetParent);if(n){n.click();return true}return false})()")
                await asyncio.sleep(0.5)
                if not moved: break
        b.proc.kill()
    print("findings:", found)
    return 1 if found else 0
sys.exit(asyncio.run(main()))
