import html,json,os,re,threading,uuid,base64
from datetime import datetime,timezone
from html.parser import HTMLParser
from urllib.parse import urlparse
import requests
from flask import Blueprint,jsonify,redirect,render_template,request,url_for
bp=Blueprint('announcements',__name__); lock=threading.RLock(); items=[]; loaded=False; sha=None
token=(os.environ.get('PUSH_GITHUB_TOKEN') or os.environ.get('GITHUB_TOKEN','')).strip()
repo=(os.environ.get('PUSH_GITHUB_REPO') or os.environ.get('GITHUB_REPO','')).strip()
branch=os.environ.get('PUSH_GITHUB_BRANCH',os.environ.get('GITHUB_BRANCH','main'))
path=os.environ.get('ANNOUNCEMENTS_GITHUB_PATH','announcements.json')
local=os.environ.get('ANNOUNCEMENTS_FILE',os.path.join(os.getcwd(),'announcements.json'))
palette=['#007bff','#4da3ff','#faa41a','#e8930f','#ff8c00','#d32f2f']
allowed={'b','strong','i','em','u','s','del','mark','small','p','br','ul','ol','li','blockquote','code','a'}
def pastel_color(c):
 c=c if re.fullmatch(r'#[0-9a-fA-F]{6}',str(c or '')) else '#007bff'
 rgb=[int(c[i:i+2],16) for i in (1,3,5)]
 return '#'+''.join(f'{round(255*0.86+v*0.14):02x}' for v in rgb)
def darken_color(c):
 c=c if re.fullmatch(r'#[0-9a-fA-F]{6}',str(c or '')) else '#007bff'
 rgb=[int(c[i:i+2],16) for i in (1,3,5)]
 return '#'+''.join(f'{round(v*0.8):02x}' for v in rgb)
def dark_pastel_color(c):
 c=c if re.fullmatch(r'#[0-9a-fA-F]{6}',str(c or '')) else '#007bff'
 rgb=[int(c[i:i+2],16) for i in (1,3,5)]
 return '#'+''.join(f'{round(30*0.86+v*0.14):02x}' for v in rgb)
class Clean(HTMLParser):
 def __init__(self): super().__init__(convert_charrefs=True); self.out=[]; self.stack=[]; self.skip=0
 def handle_starttag(self,t,attrs):
  t=t.lower()
  if t in ('script','style','iframe','object','svg','math'): self.skip+=1; return
  if self.skip or t not in allowed:return
  if t=='a':
   h=dict(attrs).get('href',''); scheme=urlparse(h).scheme.lower()
   if h and (not scheme or scheme in ('http','https','mailto')) and not h.strip().lower().startswith(('javascript:','data:')): self.out.append('<a href="'+html.escape(h,quote=True)+'" rel="noopener noreferrer">')
   else:self.out.append('<a>')
  else:self.out.append('<'+t+'>')
  if t!='br':self.stack.append(t)
 def handle_endtag(self,t):
  t=t.lower()
  if self.skip:
   if t in ('script','style','iframe','object','svg','math'):self.skip-=1
   return
  if t in self.stack:
   while self.stack:
    x=self.stack.pop();self.out.append('</'+x+'>')
    if x==t:break
 def handle_data(self,d):
  if not self.skip:self.out.append(html.escape(d))
 def result(self):
  self.close()
  while self.stack:self.out.append('</'+self.stack.pop()+'>')
  return ''.join(self.out)
def clean(v):
 p=Clean();p.feed(str(v or '')[:10000]);return p.result()
def url():return 'https://api.github.com/repos/'+repo+'/contents/'+path
def headers(accept='application/vnd.github+json'):
 return {'Authorization':'Bearer '+token,'Accept':accept,'X-GitHub-Api-Version':'2022-11-28'}
def load():
 global loaded,items,sha
 if loaded:return
 with lock:
  if loaded:return
  if token and repo:
   try:
    r=requests.get(url(),headers=headers('application/vnd.github.raw+json'),params={'ref':branch},timeout=10)
    if r.status_code==200:
     d=r.json()
     if isinstance(d,list):items=d
     m=requests.get(url(),headers=headers(),params={'ref':branch},timeout=10)
     if m.ok:sha=m.json().get('sha')
   except Exception:pass
  if not items and os.path.exists(local):
   try:
    with open(local,encoding='utf-8') as f:d=json.load(f)
    if isinstance(d,list):items=d
   except Exception:pass
  for x in items:
   if str(x.get('accent_color','')).lower()=='#4f7ef0':x['accent_color']='#007bff'
   if not re.fullmatch(r'#[0-9a-fA-F]{6}',str(x.get('dark_accent_color',''))):x['dark_accent_color']=darken_color(x.get('accent_color'))
  loaded=True
def save():
 global sha
 data=json.dumps(items,ensure_ascii=False,indent=2)
 with open(local+'.tmp','w',encoding='utf-8') as f:f.write(data)
 os.replace(local+'.tmp',local)
 if not(token and repo):return
 body={'message':'chore: 공지사항 저장','content':base64.b64encode(data.encode()).decode(),'branch':branch}
 if sha:body['sha']=sha
 r=requests.put(url(),headers=headers(),json=body,timeout=15)
 if not r.ok:raise RuntimeError('GitHub 공지 저장 실패 HTTP '+str(r.status_code))
 sha=r.json()['content']['sha']
def init_announcements(app,admin_check):
 load()
 @bp.route('/api/announcements')
 def public_list():
  load();r=jsonify([{'id':x['id'],'revision':x['revision'],'html':x['html'],'accent_color':x.get('accent_color','#007bff'),'background_color':pastel_color(x.get('accent_color','#007bff')),'dark_accent_color':x.get('dark_accent_color') or darken_color(x.get('accent_color')),'dark_background_color':dark_pastel_color(x.get('dark_accent_color') or darken_color(x.get('accent_color')))} for x in items if x.get('active')]);r.headers['Cache-Control']='no-store';return r
 @bp.route('/admin/announcements',methods=['GET','POST'])
 def admin_page():
  auth=admin_check()
  if auth is not None:return auth
  load();edit=next((x for x in items if x.get('id')==request.args.get('edit')),None)
  if request.method=='POST':
   with lock:
    action=request.form.get('action','save');item=next((x for x in items if x.get('id')==request.form.get('id')),None)
    if action=='delete':items[:]=[x for x in items if x.get('id')!=request.form.get('id')]
    elif action=='toggle' and item:item['active']=not item.get('active',True);item['revision']=datetime.now(timezone.utc).isoformat()
    elif action=='save':
     content=clean(request.form.get('content',''))
     if not content.strip():return render_template('admin_announcements.html',items=items,palette=palette,edit=None,saved=False)
     if not item:item={'id':uuid.uuid4().hex,'active':True,'order':len(items)};items.append(item)
     c=request.form.get('accent_color','');c=c if re.fullmatch(r'#[0-9a-fA-F]{6}',c) else '#007bff';d=request.form.get('dark_accent_color','');item.update({'html':content,'accent_color':c,'dark_accent_color':d if re.fullmatch(r'#[0-9a-fA-F]{6}',d) else darken_color(c),'revision':datetime.now(timezone.utc).isoformat()})
    items.sort(key=lambda x:x.get('order',0));save()
   return redirect(url_for('announcements.admin_page',saved='1'))
  return render_template('admin_announcements.html',items=items,palette=palette,edit=edit,dark_accent_color=darken_color(edit.get('accent_color') if edit else '#007bff'),saved=request.args.get('saved'))
 app.register_blueprint(bp)
