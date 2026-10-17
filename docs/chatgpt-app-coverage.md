# Copertura delle app della directory ChatGPT

Rilevazione: **16 ottobre 2026**, browser pubblico senza accesso. [Directory richiesta](https://chatgpt.com/apps) → [directory Plugins](https://chatgpt.com/plugins). Il file [JSON](chatgpt-app-coverage.json) conserva l’intero inventario osservato, l’ordine delle card per categoria e lo stato di ogni nome.

Osservate **16 categorie, 4,219 occorrenze di card e 4,133 nomi distinti**. Alcuni ID distinti hanno lo stesso nome: il numero di nomi non è un numero di app univoche. La vista può variare per regione, lingua, account e data; questa fotografia non include integrazioni private o non esposte dalla directory pubblica.

## Come leggere lo stato

La presenza nella directory dimostra che una card è pubblicata. Non dimostra che il servizio esponga un’API/MCP riutilizzabile, che OpenAgent possa riusare la registrazione OAuth di ChatGPT, né che siano disponibili le stesse operazioni o la stessa UI. Anche la [documentazione ufficiale OpenAI](https://learn.chatgpt.com/docs/plugins) distingue scoperta e uso delle integrazioni.

Il precedente [pacchetto condiviso 0.1.4](https://github.com/openagent-uno/openagent-tools/releases/tag/connectors-v0.1.4) è pubblicato dal sorgente `709e6634edbf71c6d53711b01482a0509eb7bfa0`: 14 adapter ufficiali implementati più Custom MCP. GitHub espone 17 operazioni, Notion 8, Slack 9 e Atlassian/Jira 9. La qualifica seriale remota comprende race, vet, vulnerabilità, sei bundle, installazione normale e smoke nativo Linux x64; gli altri target sono cross-compilati e verificati tramite checksum/toolchain. I pin dei prodotti rimangono indipendenti. GitHub, Notion e Slack hanno completato soltanto i rispettivi collaudi reali limitati descritti nelle [ricevute del prodotto](https://openagent.uno/guide/chatgpt-apps); Jira attende custodia del segreto e consenso reale. Dal 17 ottobre il broker espone il consenso comune pubblico per **ClickUp, GitHub e Notion**: il [checkpoint public-beta3](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/oauth-public-beta-2026-10-17.json) riguarda configurazione e readiness, senza nuovi grant o collaudi di ciclo OAuth. `beta3` identifica questo checkpoint del broker, non una versione del prodotto. Gli altri provider mantengono i rispettivi gate. L'inventario JSON conserva la fotografia originale e i suoi conteggi storici; la [ricevuta di pubblicazione](connector-release-0.1.4-publication.json) identifica gli artefatti storici 0.1.4. Il [checkpoint sorgente/registrazioni](../deploy/connector-auth/qualification-2026-10-16.md) distingue le prove dalle attivazioni.

Il sorgente [`7967195`](https://github.com/openagent-uno/openagent-tools/commit/7967195e9e45502c2d8b4f82414f7da780788045) è pubblicato come [**SDK 0.1.5**](https://github.com/openagent-uno/openagent-tools/releases/tag/connectors-v0.1.5), con **16 adapter ufficiali più Custom MCP**. Exa e Firecrawl espongono due strumenti di lettura ciascuno, tramite MCP ufficiale keyless. La **qualifica remota SDK è completata**: race, vet, vulnerabilità, sei piattaforme/dodici binari, adapter Python, smoke nativo e acquisizione da server 39. Gli **11 artefatti pubblici sono verificati tramite digest**, compreso il manifest letto senza autenticazione. La [ricevuta SDK](connector-keyless-0.1.5-qualification.json) conserva il legame fra sorgente e release. Anche [server e CLI 42 sono pubblici](https://github.com/openagent-uno/openagent/releases/tag/v1.1.0-beta.42): adottano SDK 0.1.5; il collaudo provider limitato effettuato su 41 e quello dell’installer 42 sono distinti, mentre pubblicazione e accettazione App 19 restano separate. Gli altri target non sono dichiarati tutti eseguiti nativamente. La connessione conserva autorizzazione e isolamento locali; `auth=none` richiede un contratto esplicito senza token, con endpoint e strumenti compilati. Nessun fallback autenticato o a pagamento.

Il 17 ottobre sono riuscite quattro chiamate reali limitate tramite runner: Exa Search (681 ms, 323 byte), Fetch (982 ms, 1.376 byte), Firecrawl Search (1.544 ms, 1.306 byte) e Scrape (2.956 ms, 6.686 byte), tutte HTTP 200 e un solo tentativo. **La ricerca Exa prova il successo API, non la pertinenza**: la risposta non conteneva il marker OpenAgent. Queste prove SDK restano distinte dal successivo collaudo del prodotto.

La [ricevuta del percorso server/CLI 41](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/keyless-product-1.1.0b41-2026-10-17.json) registra due connessioni normali e **quattro ulteriori letture reali totali** tramite CLI certificata, Iroh/gateway e workflow autorizzati: Fetch Exa e Scrape Firecrawl prima e dopo un riavvio effettivo. Le connessioni hanno conservato gli stessi ID; disconnessione, tombstone disabilitate, rimozione delle sorgenti MCP e arresto dei processi QA sono verificati. Nessun token, consenso OAuth, LLM o chiamata diretta al runner nel collaudo prodotto. Il primo installer pubblico 41 è **RED per EXDEV** fra mount diversi; il normale recupero con lo stesso script/prefix e `TMPDIR` owned sul mount di installazione è **PASS**, senza qualificare un'installazione vergine fra filesystem diversi. Gli errori del solo harness sono conservati separatamente. Il successivo [server/CLI 42](https://github.com/openagent-uno/openagent/releases/tag/v1.1.0-beta.42) è pubblico: 149 fixture installate e 15 casi di acquisizione sono PASS, così come il [nuovo installer pubblico fra filesystem distinti](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/product42-public-installer-2026-10-17.json), senza workaround. Il codice provider è invariato; le chiamate reali restano prove effettuate su 41, non nuovi collaudi provider su 42. App 19 è ancora in recupero della qualifica nativa ARM, senza pubblicazione o accettazione GUI dichiarata. Non si stabiliscono copertura di tutti gli strumenti o parità ChatGPT.

“Interfaccia non stabilita da questo audit” significa ricerca ancora necessaria, non “il provider non ha API”. Le fonti primarie API/MCP sono state verificate per 32 nomi; le nuove ricerche rimangono separate dal codice implementato. Tutti gli altri nomi rimangono nel backlog esplicito del JSON. Un MCP configurabile dall’utente non viene contato automaticamente come connector ufficiale pronto.

## Sei ulteriori interfacce Popular: ricerca, non implementazione

La [ricevuta primaria del 17 ottobre](chatgpt-primary-interface-audit-2026-10-17.json) documenta Remote Desktop Commander (1), Flaim Fantasy (3), WPVibe (5), Windsor.ai (11), Upwork (14) e Granola (19). Restano tutti **non implementati/non qualificati** nel catalogo ufficiale. Granola, Windsor e Upwork documentano MCP OAuth con registrazione dinamica del client (DCR): per quel percorso non serve presumere una nuova app manuale OpenAgent, ma account, consenso e compatibilità del client vanno ancora qualificati. Il percorso GraphQL di Upwork ha registrazione/chiavi proprie, separata dal suo MCP. Remote Desktop Commander richiede anche agent e pairing; Flaim una lega autorizzata; WPVibe login e autorizzazione WordPress. DCR per questi ultimi tre non è stabilito dalle fonti correnti. Nessuno dei sei è una nuova lettura pubblica `auth=none` già pronta. Il JSON conserva le letture documentali non disponibili (WPVibe nella rilettura indipendente, Upwork403 e vecchia pagina Flaim404); non sono state eseguite registrazioni o chiamate MCP/API.

## Categorie osservate

| Categoria | Card | Fonte |
| --- | ---: | --- |
| Popular | 50 | [Directory](https://chatgpt.com/plugins?category=featured) |
| New & Noteworthy | 15 | [Directory](https://chatgpt.com/plugins?category=new-and-noteworthy) |
| Small Business | 15 | [Directory](https://chatgpt.com/plugins?category=small-business) |
| Productivity | 597 | [Directory](https://chatgpt.com/plugins?category=productivity) |
| Creativity | 256 | [Directory](https://chatgpt.com/plugins?category=creativity) |
| Developer Tools | 358 | [Directory](https://chatgpt.com/plugins?category=developer-tools) |
| Business & Operations | 629 | [Directory](https://chatgpt.com/plugins?category=business-and-operations) |
| Data & Analytics | 332 | [Directory](https://chatgpt.com/plugins?category=data-and-analytics) |
| Communication | 58 | [Directory](https://chatgpt.com/plugins?category=communication) |
| Education | 337 | [Directory](https://chatgpt.com/plugins?category=education-and-research) |
| Scientific Research | 18 | [Directory](https://chatgpt.com/plugins?category=scientific-research) |
| Security | 33 | [Directory](https://chatgpt.com/plugins?category=security) |
| Finance | 462 | [Directory](https://chatgpt.com/plugins?category=finance) |
| Healthcare | 112 | [Directory](https://chatgpt.com/plugins?category=healthcare) |
| Travel | 446 | [Directory](https://chatgpt.com/plugins?category=travel) |
| Other | 501 | [Directory](https://chatgpt.com/plugins?category=other) |

Le occorrenze sono conservate per categoria e possono ripetersi fra categorie. Nel JSON `apps` raggruppa i nomi esatti; `categories[].ordered_names` preserva le singole posizioni. I link di dettaglio sono inclusi solo quando effettivamente osservati, senza inventare ID.

## Prime 50: ordine visibile in Popular → See More

È l’ordine editoriale mostrato dalla directory durante la rilevazione, **non una classifica di adozione**. La priorità iniziale può seguire questo ordine; fattibilità, permessi e condizioni del provider restano verifiche separate.

| Posizione | App | OpenAgent | Interfaccia verificata |
| ---: | --- | --- | --- |
| 1 | [Remote Desktop Commander](https://chatgpt.com/plugins/plugin_asdk_app_6a057d268ebc81919918d37eec718425) | Da implementare/qualificare | [MCP remoto OAuth/PKCE e pairing dispositivo](https://github.com/desktop-commander/remote-desktop-commander) |
| 2 | [Google Drive](https://chatgpt.com/plugins/plugin_connector_1p_ab21a553bfbc81919ea8fd1858e3ffa7) | Adapter presente; qualifica separata | [API pubblica documentata](https://developers.google.com/workspace/drive/api/guides/about-sdk) |
| 3 | [Flaim Fantasy](https://chatgpt.com/plugins/plugin_asdk_app_69a8f78087e081919e52cacacf00ff36) | Da implementare/qualificare | [MCP custom OAuth documentato](https://flaim.app/docs/custom-connectors) |
| 4 | [Atlassian](https://chatgpt.com/plugins/plugin_asdk_app_6a83901dde988191b3f3cefdcc19acfa) | SDK 0.1.4 pubblicato: 9 tool Jira; custodia segreto, OAuth e prodotto pendenti | [Jira REST API](https://developer.atlassian.com/cloud/jira/platform/rest/v3/intro/); [MCP separato con condizioni commerciali](https://support.atlassian.com/atlassian-ai-gateway/docs/get-started-with-the-atlassian-remote-mcp-server/) |
| 5 | [WPVibe](https://chatgpt.com/plugins/plugin_asdk_app_6a244fb509e481918985fee76373b0f9) | Da implementare/qualificare | [MCP OAuth per client indipendenti](https://wpvibe.ai/docs/ai-client-setup/) |
| 6 | [GitHub](https://chatgpt.com/plugins/plugin_connector_1p_1a69035c238881919c4190932b2df699) | SDK 0.1.4 pubblicato: 17 tool; consenso comune pubblico, copertura strumenti e accettazione App separate | [REST API](https://docs.github.com/en/rest); [MCP ufficiale documentato](https://github.com/github/github-mcp-server) |
| 7 | [Health](https://chatgpt.com/plugins/plugin_connector_1p_e569f8b8dfd08191903c9bd2cd7da9ac) | Da implementare/qualificare | Da verificare |
| 8 | [Outlook Email](https://chatgpt.com/plugins/plugin_connector_1p_6bcb5879c73c819196abc70016166099) | Da implementare/qualificare | [API pubblica documentata](https://learn.microsoft.com/en-us/graph/api/resources/mail-api-overview?view=graph-rest-1.0) |
| 9 | [Supabase](https://chatgpt.com/plugins/plugin_asdk_app_69d3e5ee6a708191baa733f7b8931995) | Da implementare/qualificare | [MCP ufficiale documentato](https://supabase.com/docs/guides/ai-tools/mcp) |
| 10 | [Firecrawl](https://chatgpt.com/plugins/plugin_asdk_app_6a314a73f8ac819195b0d55e36b9c609) | SDK 0.1.5/server 42 pubblici, fresh installer PASS; Scrape/lifecycle limitato su 41 PASS, App separata | [MCP keyless ufficiale](https://docs.firecrawl.dev/mcp-server/keyless) |
| 11 | [Windsor.ai](https://chatgpt.com/plugins/plugin_asdk_app_694a52cfaa3c819192bea84eaa254968) | Da implementare/qualificare | [MCP OAuth con DCR](https://mcp.windsor.ai/) |
| 12 | [Exa](https://chatgpt.com/plugins/plugin_asdk_app_69ea4ed2cf7c8191b742ef3622479ddd) | SDK 0.1.5/server 42 pubblici, fresh installer PASS; Fetch/lifecycle limitato su 41 PASS, App separata | [MCP keyless ufficiale](https://exa.ai/docs/get-started/exa-mcp) |
| 13 | [Render](https://chatgpt.com/plugins/plugin_asdk_app_6a624c56bfe081918f7544f7d58f6faf) | Da implementare/qualificare | [MCP ufficiale documentato](https://render.com/docs/mcp-server) |
| 14 | [Upwork](https://chatgpt.com/plugins/plugin_asdk_app_6a75165ed2d8819182548553aa4cb6d5) | Da implementare/qualificare | [MCP ufficiale](https://www.upwork.com/ai/mcp?trk=public_profile__reactions-text); [manifest vendor](https://github.com/upwork/upwork-agent-plugin/blob/master/mcp.json) |
| 15 | [Notion](https://chatgpt.com/plugins/plugin_asdk_app_69c18c28f1188191bf5b8445c4ab0a2e) | SDK 0.1.4 pubblicato: 8 tool; consenso comune pubblico, copertura strumenti e accettazione App separate | [REST API versionata](https://developers.notion.com/reference/versioning); [MCP ufficiale documentato](https://developers.notion.com/guides/mcp/overview) |
| 16 | [Slack](https://chatgpt.com/plugins/plugin_asdk_app_69a1d78e929881919bba0dbda1f6436d) | SDK 0.1.4 pubblico: 9 tool; [lifecycle QA limitato 16 ottobre PASS](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/slack-oauth-2026-10-16.json), distribuzione/common enrollment OFF | [Web API](https://docs.slack.dev/apis/); [MCP separato soggetto ad approvazione](https://docs.slack.dev/ai/slack-mcp-server/) |
| 17 | [Parallel Search](https://chatgpt.com/plugins/plugin_asdk_app_69fb9378663481919a68e8a2109644e5) | Ricerca keyless completata; nessuna implementazione/qualifica | [MCP ufficiale](https://docs.parallel.ai/integrations/mcp/search-mcp) |
| 18 | [Shopify](https://chatgpt.com/plugins/plugin_asdk_app_69e65c430b3081919aa4d962ab5d1698) | Adapter presente; common OAuth bloccato | [API pubblica documentata](https://shopify.dev/docs/api/admin-graphql/latest) |
| 19 | [Granola](https://chatgpt.com/plugins/plugin_asdk_app_697761cab6f48191b5ed345919a3ce8b) | Da implementare/qualificare | [MCP OAuth con DCR](https://docs.granola.ai/help-center/sharing/integrations/mcp) |
| 20 | [Klaviyo](https://chatgpt.com/plugins/plugin_asdk_app_694421e60cc88191a1e5bb4aa79950e4) | Da implementare/qualificare | [API pubblica documentata](https://developers.klaviyo.com/en/reference/api_overview) |
| 21 | [SentinelX](https://chatgpt.com/plugins/plugin_asdk_app_69f63e01766881919640f03b5e7912a5) | Da implementare/qualificare | Da verificare |
| 22 | [TinyFish](https://chatgpt.com/plugins/plugin_asdk_app_695325bae7348191b58ae9349a963d22) | Da implementare/qualificare | Da verificare |
| 23 | [Wispr Flow](https://chatgpt.com/plugins/plugin_asdk_app_6a5ae9736be0819199d06d61ac171080) | Da implementare/qualificare | Da verificare |
| 24 | [Canva](https://chatgpt.com/plugins/plugin_connector_68df33b1a2d081918778431a9cfca8ba) | Da implementare/qualificare | [API pubblica documentata](https://www.canva.dev/docs/apps/rest-apis/) |
| 25 | [Railway](https://chatgpt.com/plugins/plugin_asdk_app_6a502589384081919c5decf93496c9d1) | Da implementare/qualificare | [MCP ufficiale documentato](https://docs.railway.com/ai/mcp-server) |
| 26 | [Adspirer](https://chatgpt.com/plugins/plugin_asdk_app_69461dc91ee48191ae4a14eb9bde1c21) | Da implementare/qualificare | Da verificare |
| 27 | [Vercel](https://chatgpt.com/plugins/plugin_connector_690a90ec05c881918afb6a55dc9bbaa1) | Da implementare/qualificare | [MCP ufficiale documentato](https://vercel.com/docs/agent-resources/vercel-mcp) |
| 28 | [Otter.ai](https://chatgpt.com/plugins/plugin_asdk_app_695d84e2f06c8191861b9bac9b3fd53b) | Da implementare/qualificare | Da verificare |
| 29 | [GitLab (Beta)](https://chatgpt.com/plugins/plugin_connector_1p_5925693c1aa88191a4959257e60d0734) | Da implementare/qualificare | [MCP ufficiale documentato](https://docs.gitlab.com/user/model_context_protocol/mcp_server/) |
| 30 | [HubSpot](https://chatgpt.com/plugins/plugin_asdk_app_697acb8e53d88191bf7a79e62012ae14) | Da implementare/qualificare | [MCP ufficiale documentato](https://developers.hubspot.com/ai-tools/mcp) |
| 31 | [GSC Wizard](https://chatgpt.com/plugins/plugin_asdk_app_6a258ab1e0908191aa647c33299ad14c) | Da implementare/qualificare | Da verificare |
| 32 | [vidIQ](https://chatgpt.com/plugins/plugin_asdk_app_69dd11f3e50c8191b1ca48d03cf7e2ad) | Da implementare/qualificare | Da verificare |
| 33 | [Asana](https://chatgpt.com/plugins/plugin_asdk_app_69616780bd208191b4fb44ba44f72b61) | Da implementare/qualificare | [API pubblica documentata](https://developers.asana.com/docs/overview) |
| 34 | [Metricool](https://chatgpt.com/plugins/plugin_asdk_app_69d73fc8aa5c8191bec1583760b130c7) | Da implementare/qualificare | Da verificare |
| 35 | [Superhuman Mail](https://chatgpt.com/plugins/plugin_asdk_app_69a21e4058dc8191a6220fa911310d7b) | Da implementare/qualificare | Da verificare |
| 36 | [IOL invertironline](https://chatgpt.com/plugins/plugin_asdk_app_6a207f00eed0819181227b2ea257ff0b) | Da implementare/qualificare | Da verificare |
| 37 | [Fathom](https://chatgpt.com/plugins/plugin_asdk_app_69d88b99c5c481918e8da9225737e1e9) | Da implementare/qualificare | Da verificare |
| 38 | [Fireflies](https://chatgpt.com/plugins/plugin_connector_6912075cb358819187346bcafb601db8) | Da implementare/qualificare | Da verificare |
| 39 | [ClickUp](https://chatgpt.com/plugins/plugin_asdk_app_69431e6d26b88191b4029488aeb42f5b) | Adapter presente; consenso comune pubblico, qualifica delimitata | [API pubblica documentata](https://developer.clickup.com/) |
| 40 | [Interactive Brokers (IBKR)](https://chatgpt.com/plugins/plugin_asdk_app_69bc11db874881918718abaca20b68ce) | Da implementare/qualificare | Da verificare |
| 41 | [Todoist: To Do List & Calendar](https://chatgpt.com/plugins/plugin_asdk_app_6943b73823548191a9f9216c6790c453) | Da implementare/qualificare | Da verificare |
| 42 | [Opera Browser Connector](https://chatgpt.com/plugins/plugin_asdk_app_69d669e1d5c88191957786fbcd38b411) | Da implementare/qualificare | Da verificare |
| 43 | [Ahrefs](https://chatgpt.com/plugins/plugin_asdk_app_6966958473488191b775fdb667c52eab) | Da implementare/qualificare | [MCP commerciale con restrizioni di client](https://docs.ahrefs.com/en/mcp/docs/introduction); [API su piano commerciale](https://docs.ahrefs.com/en/api/docs/introduction) |
| 44 | [monday.com](https://chatgpt.com/plugins/plugin_connector_690aabb71bf481918b8d5b614ed3fd4c) | Da implementare/qualificare | [API pubblica documentata](https://developer.monday.com/api-reference/docs/basics) |
| 45 | [Tredict](https://chatgpt.com/plugins/plugin_asdk_app_69aef5b699a0819184512d57743fc1cd) | Da implementare/qualificare | Da verificare |
| 46 | [Webflow](https://chatgpt.com/plugins/plugin_asdk_app_6a0783a98c4c8191841404d786d4a4b9) | Da implementare/qualificare | [API pubblica documentata](https://developers.webflow.com/data/reference/rest-introduction) |
| 47 | [HYPD AI - Paid Ads & Analytics](https://chatgpt.com/plugins/plugin_asdk_app_6a3170ea7fc88191be6c0b9ff250a4b4) | Da implementare/qualificare | Da verificare |
| 48 | [SharePoint](https://chatgpt.com/plugins/plugin_connector_1p_dca009ae2c848191ae14df3a47c5e7fd) | Da implementare/qualificare | [API pubblica documentata](https://learn.microsoft.com/en-us/graph/api/resources/sharepoint?view=graph-rest-1.0) |
| 49 | [Floot](https://chatgpt.com/plugins/plugin_asdk_app_6a500d350f8c819194e30335a7b134af) | Da implementare/qualificare | Da verificare |
| 50 | [Quo](https://chatgpt.com/plugins/plugin_asdk_app_69e6af3297d88191b4925772c50df286) | Da implementare/qualificare | Da verificare |

## Confini già noti

- **Google Drive e Gmail:** il codice esiste; verifica OAuth, scope e requisiti di sicurezza Google restano distinti dalla disponibilità del codice.
- **ClickUp:** consenso comune pubblico abilitato il 17 ottobre; adapter e percorso common OAuth hanno una qualifica reale delimitata, descritta nel [checkpoint del broker](../deploy/connector-auth/qualification-2026-10-14.md). Non estende l’accettazione ad altri provider.
- **Shopify:** adapter presente, iscrizione common ancora disattivata finché privacy, webhook e ciclo credenziali sullo stesso negozio con due server non sono qualificati.
- **GitHub e Notion:** adapter pubblicati in SDK 0.1.4 e consenso comune pubblico abilitato il 17 ottobre. I collaudi limitati già citati restano separati dalla copertura di tutti gli strumenti e dall’accettazione delle operazioni nella App nativa. Il checkpoint pubblico del broker non aggiunge un nuovo collaudo OAuth.
- **Slack:** SDK 0.1.4 pubblica nove tool Web API typed mantenendo l’ID `slack-import`, provider `slack_import` e capability Social. La [ricevuta QA del 16 ottobre](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/slack-oauth-2026-10-16.json) conserva consenso, letture autorizzate, messaggio create/read/delete con pulizia verificata, rinnovo dopo recupero esplicito, lettura dopo restart e disconnessione locale. La precedente ricevuta descrive correttamente il candidato allora non pubblicato e rimane immutata; **distribuzione pubblica e common enrollment sono ancora OFF**. Non sono qualificati tutti i tool, la App nativa o il [MCP ufficiale](https://docs.slack.dev/ai/slack-mcp-server/), che richiede approvazione separata. History/replies restano limitati a 15 messaggi senza retry automatico, rispettando il [confine delle app commerciali non Marketplace](https://docs.slack.dev/changelog/2025/05/29/rate-limit-changes-for-non-marketplace-apps/).
- **Ahrefs:** [MCP commerciale](https://docs.ahrefs.com/en/mcp/docs/introduction) e [API pubblica](https://docs.ahrefs.com/en/api/docs/introduction) hanno condizioni differenti. La documentazione vieta bridge/script/client HTTP autonomi sull’MCP esterno: usare l’API supportata o ottenere autorizzazione esplicita.
- **Atlassian:** nove tool candidati Jira REST, con sito `cloud_id` scelto dall’host e mai dagli argomenti del modello. App creata, callback e due scope classici read/write salvati; custodia del segreto e consenso reale per il sito restano pendenti. La qualifica delle API non estende l’accettazione a Confluence o al [MCP Rovo](https://support.atlassian.com/atlassian-ai-gateway/docs/get-started-with-the-atlassian-remote-mcp-server/), che conserva condizioni e crediti separati.
- **Outlook Email e SharePoint:** le API Microsoft Graph documentate non sono equivalenti a un accesso generico IMAP o all’intera esperienza ChatGPT.

## Prossime tre integrazioni senza nuove registrazioni

Questa è ricerca su fonti primarie, senza implementazioni o chiamate ai dati dei provider. Parallel segue la posizione editoriale 17 di Popular; Context7 e CoinGecko sono presenti nelle altre categorie, senza posizione Popular registrata.

| Provider | Superficie minima proponibile | Autenticazione e limiti |
| --- | --- | --- |
| [Parallel Search](https://docs.parallel.ai/integrations/mcp/search-mcp) | MCP `web_search` e `web_fetch`, con query e URL limitati | Endpoint `/mcp` anonimo gratuito, modalità fast e quote ridotte. Eventuale `session_id` deriva dalla conversazione dell’host; niente cambi di identità o configurazione a pagamento negli argomenti. |
| [Context7](https://github.com/upstash/context7/blob/master/packages/mcp/README.md) | MCP `resolve-library-id` e `query-docs` per documentazione pubblica | Endpoint `https://mcp.context7.com/mcp`, uso base senza chiave documentato. Quote anonime; repository privati, indicizzazione e accesso autenticato esclusi. |
| [CoinGecko](https://docs.coingecko.com/ai-integration/mcp-server) | Letture pubbliche di prezzi e dati globali | Endpoint gratuito keyless `https://mcp.api.coingecko.com/mcp`, quote condivise. Il [contratto corrente](https://docs.coingecko.com/ai-integration/mcp-tools) espone `search_docs` ed `execute`: servono template SDK di sola lettura compilati e argomenti validati; nessuna interfaccia TypeScript arbitraria. Schema e metodi del sottoinsieme gratuito vanno qualificati prima di aggiungere la card. |

Nessuna delle tre è già un connector ufficiale OpenAgent. Il trasporto keyless non sostituisce il binding autorizzato della connessione. Il [setup generale Blockscout](https://github.com/blockscout/mcp-server) richiede oggi una chiave PRO dal Developer Portal anche sul piano gratuito: non rientra in questo gruppo senza registrazioni.

## Catalogo OpenAgent fuori dal confronto dei soli nomi Popular

Il JSON conserva tutte le voci del catalogo sorgente, anche se il relativo nome non compare nella fotografia pubblica. Gmail, Postiz, Pipeboard Ads, Replio, BillingBear, Google Analytics e IMAP Email non devono essere scartati solo perché non sono nelle prime 50. Una corrispondenza nominale con una card non prova identità del provider né parità delle funzioni.

## Lavoro necessario per coprire tutte le voci

1. Conservare questa fotografia come backlog completo delle card osservate e risolvere gli omonimi tramite ID pubblico prima di creare registrazioni.
2. Adottare SDK/runner 0.1.5 pubblico nei prodotti e qualificare il percorso Exa/Firecrawl attraverso workflow e App; rilascio server 41/App 19 e relativa accettazione restano separati. Per gli adapter già pubblicati, completare i gate ancora aperti per strumenti, App nativa e consenso generale dei provider rimasti chiusi; il consenso pubblico ClickUp/GitHub/Notion non estende l’accettazione agli altri.
3. Per ogni voce verificare prima fonte ufficiale, condizioni commerciali, autenticazione e disponibilità fuori da ChatGPT. Le interfacce sconosciute restano esplicitamente da ricercare.
4. Riutilizzare un MCP ufficiale quando trasporto, autenticazione e condizioni sono compatibili; altrimenti costruire un adapter API condiviso. Un servizio chiuso o riservato a partner richiede un accordo, non un endpoint inventato.
5. Conservare token ed esecuzione nei server locali; usare il broker per i soli passaggi OAuth ammessi dal provider. Non trasferire cookie, endpoint privati o segreti di ChatGPT.
6. Qualificare discovery, lettura, scrittura autorizzata quando prevista, rinnovo se applicabile, riavvio, disconnessione e isolamento dei permessi. Registrazione, codice o catalogo da soli non sono prova di funzionamento.

L’inventario conserva l’intero backlog e la mappa delle fonti. La rilevazione originale della directory non richiedeva build o chiamate ai dati dei provider; i successivi risultati del candidato e delle registrazioni sono riportati separatamente nel checkpoint. Non vengono aggiunte automaticamente migliaia di integrazioni, attivati provider o dichiarata parità con la directory.
