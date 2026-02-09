# FofocaDoGrupo 🕵️‍♀️💬 (Enterprise Gossip Management)

Uma plataforma web (no navegador) com cara de SaaS corporativo para **gerenciar fofocas como se fossem tickets de CRM**: pipeline, tags, “confiabilidade”, dashboard e audit log.

> Projeto humorístico/educacional: é só uma brincadeira com estética enterprise. 😄

## ✨ Funcionalidades (MVP)
- Login (admin/admin)
- Criar “tickets de fofoca”
- Pipeline de status: **LEAD → APURAÇÃO → CONFIRMADO → ARQUIVADO**
- Tags e fonte
- Score de confiabilidade (0–100)
- Dashboard com KPIs
- Audit log (rastreamento de ações)

## 🧱 Stack
- Backend: **FastAPI**
- Banco: **SQLite**
- Frontend: **HTML/CSS/JS** (sem framework)

## ▶️ Como rodar localmente (Windows)
1. Instale Python 3.10+  
2. Na pasta do projeto:

```bash
py -m pip install -U pip
py -m pip install fastapi uvicorn
py -m uvicorn app:app --reload
