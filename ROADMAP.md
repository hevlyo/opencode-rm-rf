# ShellShield Roadmap

**Última atualização:** Fevereiro 2026  
**Visão geral:** Tornar o terminal seguro na era de IA coding assistants, com overhead mínimo e foco em vibecoders / power users.  
Prioridade: Alta (H) / Média (M) / Baixa (L)  
Status: ✅ Feito | 🚧 Em progresso | ⏳ Planejado | ❓ Ideia

## Visão de curto prazo (Q1-Q2 2026) — v0.5 a v1.0
Foco: Estabilizar core, ganhar tração inicial, reduzir fricção de adoção.

- [x] Hardening do installer (checksums, harden phases) ✅
- [x] Testes E2E estabilizados e demo assets atualizados ✅
- [ ] Suporte automático a aliases/functions (in-memory snapshot ou on-demand probe) 🚧
- [ ] Publicar primeira release tag (v0.1.0 beta) com changelog
- [ ] Integração seamless com bash/zsh (hook init automático)
- [ ] Seção "Why Trust This?" no README + GPG-signed install.sh
- [ ] Badges: CI, coverage, dependabot, stars goal
- [ ] Post inicial em X/Reddit/HN com demo GIFs

## Médio prazo (Q2-Q3 2026) — v1.0 a v2.0
Foco: Features que diferenciam + expansão de shells/ambientes.

- [ ] Suporte oficial a fish shell
- [ ] Modo Windows (via WSL ou native se viável)
- [ ] Public docs site (Docusaurus ou MkDocs) com rule reference completa
- [ ] Prebuilt binaries (via GitHub Releases: Linux/macOS/arm64)
- [ ] npm/Bun publish global (`bunx shellshield` ou `npm i -g shellshield`)
- [ ] Homebrew tap oficial
- [ ] Integração com tools AI: preview de comandos no Cursor/Claude/Aider
- [ ] Alertas desktop (notify-send, terminal bell custom)
- [ ] Config presets: "dev", "prod", "paranoid"

## Longo prazo (Q4 2026+) — v2.x+
Foco: Enterprise/team features + ecossistema.

- [ ] Team dashboards para audit logs (centralizado, talvez via self-hosted server)
- [ ] Análise de prompts maliciosos (regex + LLM lightweight para detectar jailbreaks)
- [ ] Plugin VSCode/Cursor que injeta ShellShield antes de executar
- [ ] Suporte a mais interpretadores (ruby -e, perl -e, etc.)
- [ ] Modo "learning" (aprende allowlists do usuário ao longo do tempo)
- [ ] Integração com 1Password/GitGuardian para segredos em comandos

## Como contribuir / Prioridades atuais
- Veja issues com label `help wanted` ou `good first issue`
- Ideias novas? Abra discussion ou issue com [RFC] no título
- Quer priorizar algo?
