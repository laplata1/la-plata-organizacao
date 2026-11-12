# LA PLATA — Publicação nova na Vercel (Node.js, sem Python)

Este projeto inclui site HTML/CSS/JavaScript e API Node.js com banco PostgreSQL compartilhado.

## Como colocar no ar
1. Crie um repositório GitHub NOVO e envie o conteúdo extraído deste ZIP para a raiz. NÃO envie app.py, lp_backend.py, pyproject.toml ou arquivos Python antigos.
2. Importe o repositório na Vercel. Framework Preset: Other; Root Directory: ./; não configure build command personalizado.
3. Crie/use seu banco PostgreSQL no Supabase. Obtenha a string de conexão (pooler, se apropriado) em Connect.
4. Na Vercel configure DATABASE_URL, SESSION_SECRET (mínimo 32 caracteres) e ADMIN_PASSWORD (mínimo 8 caracteres). NÃO coloque segredos no GitHub.
5. Faça Deploy. Teste https://SEU-DOMINIO.vercel.app/api/health. A resposta deve ser JSON com ok:true.
6. Login inicial: admin; senha definida em ADMIN_PASSWORD no PRIMEIRO acesso com banco vazio.

## Funcionalidades
- Registro pendente, aprovação de membros, gerenciamento de cargos e baús exclusivos.
- Membro vê apenas o próprio baú e histórico de farm.
- Gerentes, líderes e administradores analisam farm, estoque e histórico.
- Entradas e retiradas só alteram saldo após aprovação de outra conta autorizada.

## Observações
- Banco Supabase NÃO está conectado automaticamente; é preciso configurar DATABASE_URL.
- O projeto não foi publicado nem testado na sua conta Vercel.
- Para produção pública, é necessária revisão de segurança adicional (CSRF, limitação de tentativas, backups).
- O contador de visitas é local a cada navegador.
