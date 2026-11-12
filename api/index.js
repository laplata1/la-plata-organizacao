import {Pool} from 'pg';
import crypto from 'node:crypto';

const pool = new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_URL?.includes('localhost')?false:{rejectUnauthorized:false},max:3});
const roles=['Administrador','Gerente de Farm','Gerente de Vendas','Líder','Sub Líder','Membro'];
const leaders=roles.slice(0,5);
const itemsFarm=['Dinheiro sujo','Ópio','Folha','Seringa','Agulha','Capofol'];
const itemsStock=['Capofol','App Piston','Calibre 12','G36','M16','C4'];
const err=(status,message)=>Object.assign(new Error(message),{status});
const hash=p=>{let salt=crypto.randomBytes(16).toString('hex');return salt+':'+crypto.scryptSync(p,salt,64).toString('hex')};
const verify=(p,v)=>{try{let [s,h]=v.split(':');return crypto.timingSafeEqual(Buffer.from(h,'hex'),crypto.scryptSync(p,s,64))}catch{return false}};
const json=(res,status,data)=>res.status(status).json(data);
const clean=u=>({id:u.id,name:u.name,login:u.login,role:u.role,locker:u.locker,active:u.active,status:u.status});
const quantity=n=>Number.isSafeInteger(Number(n))&&Number(n)>0&&Number(n)<=100000000?Number(n):null;
const canManage=u=>leaders.includes(u?.role);
const admin=u=>u?.role==='Administrador';
const cookie=(req,name)=>(req.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith(name+'='))?.slice(name.length+1);
const sign=v=>crypto.createHmac('sha256',process.env.SESSION_SECRET).update(v).digest('hex');
function session(req){
 const raw=cookie(req,'lp_session');if(!raw)return null;
 const [id,exp,mac]=raw.split('.');
 if(!id||!exp||!mac||Number(exp)<Date.now())return null;
 const expected=sign(id+'.'+exp);
 if(mac.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(mac),Buffer.from(expected)))return null;
 return Number(id);
}
async function init(){
 await pool.query(`CREATE TABLE IF NOT EXISTS users(
 id BIGSERIAL PRIMARY KEY,name TEXT NOT NULL,login TEXT UNIQUE NOT NULL,
 password TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'Membro',
 locker INTEGER UNIQUE,active BOOLEAN NOT NULL DEFAULT FALSE,
 status TEXT NOT NULL DEFAULT 'Pendente',created_at TIMESTAMPTZ DEFAULT NOW())`);
 await pool.query(`CREATE TABLE IF NOT EXISTS farm(
 id BIGSERIAL PRIMARY KEY,user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
 item TEXT NOT NULL,qty BIGINT NOT NULL CHECK(qty>0),status TEXT NOT NULL DEFAULT 'Pendente',
 reviewed_by BIGINT REFERENCES users(id) ON DELETE SET NULL,created_at TIMESTAMPTZ DEFAULT NOW(),reviewed_at TIMESTAMPTZ)`);
 await pool.query(`CREATE TABLE IF NOT EXISTS stock(
 item TEXT PRIMARY KEY,qty BIGINT NOT NULL DEFAULT 0 CHECK(qty>=0))`);
 await pool.query(`CREATE TABLE IF NOT EXISTS stock_requests(
 id BIGSERIAL PRIMARY KEY,user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
 item TEXT NOT NULL,delta BIGINT NOT NULL,status TEXT NOT NULL DEFAULT 'Pendente',
 reviewed_by BIGINT REFERENCES users(id) ON DELETE SET NULL,created_at TIMESTAMPTZ DEFAULT NOW(),reviewed_at TIMESTAMPTZ)`);
 await pool.query(`CREATE TABLE IF NOT EXISTS audit(
 id BIGSERIAL PRIMARY KEY,actor BIGINT,action TEXT NOT NULL,detail TEXT,
 created_at TIMESTAMPTZ DEFAULT NOW())`);
 for(const item of itemsStock)await pool.query('INSERT INTO stock(item,qty) VALUES($1,0) ON CONFLICT DO NOTHING',[item]);
 const a=await pool.query("SELECT id FROM users WHERE login='admin'");
 if(!a.rowCount){
  if(!process.env.ADMIN_PASSWORD||process.env.ADMIN_PASSWORD.length<8)throw err(503,'Defina ADMIN_PASSWORD com pelo menos 8 caracteres.');
  await pool.query("INSERT INTO users(name,login,password,role,active,status) VALUES('Administrador','admin',$1,'Administrador',true,'Aprovado') ON CONFLICT(login) DO NOTHING",[hash(process.env.ADMIN_PASSWORD)]);
 }
}
async function actor(req){
 const id=session(req);if(!id)return null;
 const r=await pool.query("SELECT * FROM users WHERE id=$1 AND active=true AND status='Aprovado'",[id]);
 return r.rows[0]||null;
}
async function log(client,u,action,detail){await client.query('INSERT INTO audit(actor,action,detail) VALUES($1,$2,$3)',[u?.id||null,action,detail])}
const safeRole=r=>roles.includes(r)?r:null;
const cleanLogin=s=>typeof s==='string'&&/^[a-zA-Z0-9_.-]{3,40}$/.test(s);
const cleanName=s=>typeof s==='string'&&s.trim().length>=2&&s.trim().length<=80;
async function transaction(fn){
 const c=await pool.connect();
 try{await c.query('BEGIN');const v=await fn(c);await c.query('COMMIT');return v}
 catch(e){await c.query('ROLLBACK');throw e}
 finally{c.release()}
}
export default async function handler(req,res){
 res.setHeader('Cache-Control','no-store');
 res.setHeader('X-Content-Type-Options','nosniff');
 try{
  if(!process.env.DATABASE_URL||!process.env.SESSION_SECRET||process.env.SESSION_SECRET.length<32)throw err(503,'Configure DATABASE_URL e SESSION_SECRET na Vercel.');
  await init();
  const path=String(req.query.route||'').replace(/^\/|\/$/g,'');
  const method=req.method;
  const body=typeof req.body==='object'&&req.body!==null?req.body:{};
  if(path==='health')return json(res,200,{ok:true,service:'LA PLATA'});
  if(path==='register'&&method==='POST'){
   const {name,login,password}=body;
   if(!cleanName(name)||!cleanLogin(login)||typeof password!=='string'||password.length<8||password.length>200)throw err(400,'Informe nome, login válido e senha de 8 caracteres ou mais.');
   try{
    await pool.query("INSERT INTO users(name,login,password) VALUES($1,$2,$3)",[name.trim(),login.toLowerCase(),hash(password)]);
   }catch(e){if(e.code==='23505')throw err(409,'Login já cadastrado.');throw e}
   return json(res,201,{message:'Cadastro enviado para aprovação do administrador.'});
  }
  if(path==='login'&&method==='POST'){
   const r=await pool.query('SELECT * FROM users WHERE login=$1',[String(body.login||'').toLowerCase()]);
   const u=r.rows[0];
   if(!u||!verify(String(body.password||''),u.password))throw err(401,'Login ou senha inválidos.');
   if(!u.active||u.status!=='Aprovado')throw err(403,'Seu cadastro está pendente ou inativo. Aguarde a aprovação.');
   const exp=Date.now()+7*86400000,part=u.id+'.'+exp;
   res.setHeader('Set-Cookie',`lp_session=${part}.${sign(part)}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=604800`);
   return json(res,200,{user:clean(u)});
  }
  if(path==='logout'&&method==='POST'){
   res.setHeader('Set-Cookie','lp_session=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0');
   return json(res,200,{ok:true});
  }
  const u=await actor(req);
  if(!u)throw err(401,'Faça login.');
  if(path==='me')return json(res,200,{user:clean(u)});
  if(path==='overview'){
   const [members,farms,requests]=await Promise.all([
    pool.query("SELECT count(*)::int AS n FROM users WHERE status='Pendente'"),
    pool.query("SELECT count(*)::int AS n FROM farm WHERE status='Pendente'"),
    pool.query("SELECT count(*)::int AS n FROM stock_requests WHERE status='Pendente'")
   ]);
   return json(res,200,{pendingMembers:admin(u)?members.rows[0].n:0,pendingFarm:canManage(u)?farms.rows[0].n:0,pendingStock:canManage(u)?requests.rows[0].n:0});
  }
  if(path==='users'&&method==='GET'){
   if(!canManage(u))throw err(403,'Sem permissão.');
   const r=await pool.query('SELECT id,name,login,role,locker,active,status,created_at FROM users ORDER BY id DESC');
   return json(res,200,{users:r.rows});
  }
  if(path==='users'&&method==='POST'){
   if(!admin(u))throw err(403,'Apenas administrador.');
   const {name,login,password,role}=body;
   if(!cleanName(name)||!cleanLogin(login)||typeof password!=='string'||password.length<8||!safeRole(role))throw err(400,'Cadastro inválido.');
   try{
    const r=await pool.query("INSERT INTO users(name,login,password,role,active,status) VALUES($1,$2,$3,$4,true,'Aprovado') RETURNING id",[name.trim(),login.toLowerCase(),hash(password),role]);
    await log(pool,u,'Usuário criado',login);
    return json(res,201,{id:r.rows[0].id});
   }catch(e){if(e.code==='23505')throw err(409,'Login já existe.');throw e}
  }
  if(path==='user-update'&&method==='POST'){
   if(!admin(u))throw err(403,'Apenas administrador.');
   const id=Number(body.id);
   if(!Number.isSafeInteger(id))throw err(400,'ID inválido.');
   const old=(await pool.query('SELECT * FROM users WHERE id=$1',[id])).rows[0];
   if(!old)throw err(404,'Usuário não encontrado.');
   const name=body.name??old.name,login=body.login??old.login,role=body.role??old.role,active=body.active??old.active;
   if(!cleanName(name)||!cleanLogin(login)||!safeRole(role)||typeof active!=='boolean')throw err(400,'Dados inválidos.');
   if(id===u.id&&(role!=='Administrador'||!active))throw err(400,'Não é possível desativar ou rebaixar a própria conta.');
   const locker=role==='Membro'?old.locker:null;
   await pool.query('UPDATE users SET name=$1,login=$2,role=$3,active=$4,locker=$5 WHERE id=$6',[name.trim(),login.toLowerCase(),role,active,locker,id]);
   if(typeof body.password==='string'&&body.password.length>=8)await pool.query('UPDATE users SET password=$1 WHERE id=$2',[hash(body.password),id]);
   await log(pool,u,'Usuário editado',login);
   return json(res,200,{ok:true});
  }
  if(path==='user-delete'&&method==='POST'){
   if(!admin(u))throw err(403,'Apenas administrador.');
   const id=Number(body.id);
   if(id===u.id)throw err(400,'Não é possível excluir sua própria conta.');
   await pool.query('DELETE FROM users WHERE id=$1',[id]);
   await log(pool,u,'Usuário excluído',String(id));
   return json(res,200,{ok:true});
  }
  if(path==='review-user'&&method==='POST'){
   if(!admin(u))throw err(403,'Apenas administrador.');
   const r=await pool.query("UPDATE users SET status=$1,active=$2 WHERE id=$3 AND status='Pendente' RETURNING id,login",[body.approve===true?'Aprovado':'Rejeitado',body.approve===true,Number(body.id)]);
   if(!r.rowCount)throw err(404,'Cadastro pendente não encontrado.');
   await log(pool,u,'Cadastro analisado',r.rows[0].login);
   return json(res,200,{ok:true});
  }
  if(path==='assign-locker'&&method==='POST'){
   if(!admin(u))throw err(403,'Apenas administrador.');
   const id=Number(body.id),locker=body.locker===null?null:Number(body.locker);
   if(locker!==null&&(!Number.isSafeInteger(locker)||locker<1||locker>999))throw err(400,'Baú inválido (1 a 999).');
   await transaction(async c=>{
    const member=(await c.query('SELECT * FROM users WHERE id=$1 FOR UPDATE',[id])).rows[0];
    if(!member||member.role!=='Membro')throw err(400,'Selecione um membro.');
    if(locker!==null){
     const taken=await c.query('SELECT id FROM users WHERE locker=$1 AND id<>$2',[locker,id]);
     if(taken.rowCount)throw err(409,'Este baú já pertence a outro membro.');
    }
    await c.query('UPDATE users SET locker=$1 WHERE id=$2',[locker,id]);
    await log(c,u,'Baú atribuído',id+' → '+locker);
   });
   return json(res,200,{ok:true});
  }
  if(path==='farm'&&method==='GET'){
   const r=canManage(u)?await pool.query("SELECT f.*,x.name AS member_name,y.name AS reviewer_name FROM farm f LEFT JOIN users x ON x.id=f.user_id LEFT JOIN users y ON y.id=f.reviewed_by ORDER BY f.id DESC LIMIT 300"):await pool.query("SELECT f.*,x.name AS member_name,y.name AS reviewer_name FROM farm f LEFT JOIN users x ON x.id=f.user_id LEFT JOIN users y ON y.id=f.reviewed_by WHERE f.user_id=$1 ORDER BY f.id DESC LIMIT 300",[u.id]);
   return json(res,200,{farm:r.rows});
  }
  if(path==='farm'&&method==='POST'){
   if(u.role!=='Membro'||!u.locker)throw err(403,'Seu baú precisa ser atribuído pelo administrador.');
   const qty=quantity(body.qty);
   if(!itemsFarm.includes(body.item)||!qty)throw err(400,'Item ou quantidade inválida.');
   await pool.query('INSERT INTO farm(user_id,item,qty) VALUES($1,$2,$3)',[u.id,body.item,qty]);
   await log(pool,u,'Farm solicitado',body.item+' x '+qty);
   return json(res,201,{ok:true});
  }
  if(path==='review-farm'&&method==='POST'){
   if(!canManage(u))throw err(403,'Sem permissão.');
   await transaction(async c=>{
    const r=(await c.query('SELECT * FROM farm WHERE id=$1 FOR UPDATE',[Number(body.id)])).rows[0];
    if(!r||r.status!=='Pendente')throw err(404,'Solicitação pendente não encontrada.');
    if(Number(r.user_id)===Number(u.id))throw err(403,'Você não pode aprovar seu próprio lançamento.');
    await c.query('UPDATE farm SET status=$1,reviewed_by=$2,reviewed_at=NOW() WHERE id=$3',[body.approve===true?'Aprovado':'Rejeitado',u.id,r.id]);
    await log(c,u,'Farm analisado',String(r.id));
   });
   return json(res,200,{ok:true});
  }
  if(path==='stock'&&method==='GET'){
   if(!canManage(u))throw err(403,'Sem permissão.');
   const [stock,requests]=await Promise.all([pool.query('SELECT * FROM stock ORDER BY item'),pool.query('SELECT s.*,u.name AS requester,r.name AS reviewer FROM stock_requests s LEFT JOIN users u ON u.id=s.user_id LEFT JOIN users r ON r.id=s.reviewed_by ORDER BY s.id DESC LIMIT 300')]);
   return json(res,200,{stock:stock.rows,requests:requests.rows});
  }
  if(path==='stock'&&method==='POST'){
   if(!canManage(u))throw err(403,'Sem permissão.');
   const qty=quantity(body.qty);
   if(!itemsStock.includes(body.item)||!qty||!['Entrada','Retirada'].includes(body.kind))throw err(400,'Movimentação inválida.');
   await pool.query('INSERT INTO stock_requests(user_id,item,delta) VALUES($1,$2,$3)',[u.id,body.item,body.kind==='Entrada'?qty:-qty]);
   await log(pool,u,'Estoque solicitado',body.kind+' '+body.item+' x '+qty);
   return json(res,201,{ok:true});
  }
  if(path==='review-stock'&&method==='POST'){
   if(!canManage(u))throw err(403,'Sem permissão.');
   await transaction(async c=>{
    const r=(await c.query('SELECT * FROM stock_requests WHERE id=$1 FOR UPDATE',[Number(body.id)])).rows[0];
    if(!r||r.status!=='Pendente')throw err(404,'Solicitação pendente não encontrada.');
    if(Number(r.user_id)===Number(u.id))throw err(403,'Não pode aprovar a própria solicitação.');
    if(body.approve===true){
     const s=(await c.query('SELECT * FROM stock WHERE item=$1 FOR UPDATE',[r.item])).rows[0];
     if(Number(s.qty)+Number(r.delta)<0)throw err(409,'Saldo insuficiente para aprovar esta retirada.');
     await c.query('UPDATE stock SET qty=qty+$1 WHERE item=$2',[r.delta,r.item]);
    }
    await c.query('UPDATE stock_requests SET status=$1,reviewed_by=$2,reviewed_at=NOW() WHERE id=$3',[body.approve===true?'Aprovado':'Rejeitado',u.id,r.id]);
    await log(c,u,'Estoque analisado',String(r.id));
   });
   return json(res,200,{ok:true});
  }
  if(path==='history'&&method==='GET'){
   if(!canManage(u))throw err(403,'Sem permissão.');
   const r=await pool.query('SELECT a.*,u.name AS actor_name FROM audit a LEFT JOIN users u ON u.id=a.actor ORDER BY a.id DESC LIMIT 300');
   return json(res,200,{history:r.rows});
  }
  throw err(404,'Rota não encontrada.');
 }catch(e){
  console.error(e);
  return json(res,e.status||500,{error:e.status?e.message:'Erro no servidor. Confira o banco de dados e os logs da Vercel.'});
 }
}
