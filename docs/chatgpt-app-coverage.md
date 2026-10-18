# Copertura delle app della directory ChatGPT

Rilevazione: **16 ottobre 2026**, browser pubblico senza accesso. [Directory richiesta](https://chatgpt.com/apps) → [directory Plugins](https://chatgpt.com/plugins). Il file [JSON](chatgpt-app-coverage.json) conserva l’intero inventario osservato, l’ordine delle card per categoria e lo stato di ogni nome.

Osservate **16 categorie, 4,219 occorrenze di card e 4,133 nomi distinti**. Alcuni ID distinti hanno lo stesso nome: il numero di nomi non è un numero di app univoche. La vista può variare per regione, lingua, account e data; questa fotografia non include integrazioni private o non esposte dalla directory pubblica.

## Stato corrente del 18 ottobre

[SDK **0.1.8**](https://github.com/openagent-uno/openagent-tools/releases/tag/connectors-v0.1.8)
è pubblico dal sorgente `5a7dea3ec5edf183545ea703538d56b208069250`:
**114 connector ufficiali più Custom MCP**, **315 letture e 82 azioni**.
La [ricevuta pubblica](connector-sdk-0.1.8-qualification.json) registra 11 asset
verificati, race/vet/vulnerabilità, dodici binari per sei target, wheel Python,
acquisizione da host pubblico e fixture native Linux x64. Gli altri cinque
target sono cross-build, non runtime nativi qualificati.

La nuova coorte comprende **90 profili API con credenziale manuale e 180 letture**,
due per provider, più **OneDrive e SharePoint con 12 letture**. Sono sottoinsiemi
API typed e read-only con endpoint fissi: non dichiarano parità con le app
ChatGPT, l'intero MCP del vendor o una nuova registrazione OAuth. I requisiti di
permesso dei token manuali sono documentazione di setup, non scope OAuth
attestati. I metadati condivisi includono 45 marchi SVG verificati; i marchi
mancanti restano assenti. Le fixture HTTP/schema e i controlli del runner non
sono nuove chiamate o consensi reali ai provider.

[Server/CLI **44**](https://github.com/openagent-uno/openagent/releases/tag/v1.1.0-beta.44)
e [App **21**](https://github.com/openagent-uno/openagent-app/releases/tag/v1.1.0-beta.21)
restano pubblici con SDK **0.1.7** e 22 connector ufficiali. Adozione prodotto 45,
App 22 e relativa accettazione sono separate. Google Calendar e Outlook
mantengono il [contratto SDK 0.1.7](connector-calendar-mail-0.1.7-candidate.md);
nessun consenso reale Google/Microsoft o nuova attivazione comune è qualificato
con SDK 0.1.8. Anche la selezione host-owned di siti/drive Graph non concede accesso.

## Come leggere lo stato

La presenza nella directory dimostra che una card è pubblicata. Non dimostra che il servizio esponga un’API/MCP riutilizzabile, che OpenAgent possa riusare la registrazione OAuth di ChatGPT, né che siano disponibili le stesse operazioni o la stessa UI. Anche la [documentazione ufficiale OpenAI](https://learn.chatgpt.com/docs/plugins) distingue scoperta e uso delle integrazioni.

Il precedente [pacchetto condiviso 0.1.4](https://github.com/openagent-uno/openagent-tools/releases/tag/connectors-v0.1.4) è pubblicato dal sorgente `709e6634edbf71c6d53711b01482a0509eb7bfa0`: 14 adapter ufficiali implementati più Custom MCP. GitHub espone 17 operazioni, Notion 8, Slack 9 e Atlassian/Jira 9. La qualifica seriale remota comprende race, vet, vulnerabilità, sei bundle, installazione normale e smoke nativo Linux x64; gli altri target sono cross-compilati e verificati tramite checksum/toolchain. I pin dei prodotti rimangono indipendenti. GitHub, Notion e Slack hanno completato soltanto i rispettivi collaudi reali limitati descritti nelle [ricevute del prodotto](https://openagent.uno/guide/chatgpt-apps); Jira attende custodia del segreto e consenso reale. Dal 17 ottobre il broker espone il consenso comune pubblico per **ClickUp, GitHub e Notion**: il [checkpoint public-beta3](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/oauth-public-beta-2026-10-17.json) riguarda configurazione e readiness, senza nuovi grant o collaudi di ciclo OAuth. `beta3` identifica questo checkpoint del broker, non una versione del prodotto. Gli altri provider mantengono i rispettivi gate. L'inventario JSON conserva la fotografia originale e i suoi conteggi storici; la [ricevuta di pubblicazione](connector-release-0.1.4-publication.json) identifica gli artefatti storici 0.1.4. Il [checkpoint sorgente/registrazioni](../deploy/connector-auth/qualification-2026-10-16.md) distingue le prove dalle attivazioni.

Il precedente [**SDK 0.1.6**](https://github.com/openagent-uno/openagent-tools/releases/tag/connectors-v0.1.6) è pubblico e verificato dal sorgente `2ec7c114a49b72460addc00fc8e8d6547a683b59`: **19 connector ufficiali più Custom MCP**, con Parallel Search, Context7 e CoinGecko aggiunti alla precedente coorte. Gli 11 artefatti hanno digest verificati, manifest anonimo SHA256 `a1e87b9469cadfc1c8184e4ad704d0b7ed26ee7233f6145bf15baddfe19789f5` e origine Go proxy coerente. La [ricevuta SDK 16](connector-keyless-0.1.6-qualification.json) registra race/vet/vulnerabilità, sei piattaforme/dodici binari, Python, smoke nativo Linux x64 e acquisizione da server 39. Gli altri target sono cross-compilati; non si dichiarano tutti eseguiti nativamente.

Sono PASS **sei letture reali limitate**, tutte HTTP 200 con un solo tentativo: Parallel Search/Fetch, Context7 resolve/query-docs e CoinGecko price/global. Le verifiche semantiche controllano risultati/excerpt, ID biblioteca realmente restituito e poi usato, marker useEffect/cleanup e aggregati numerici/timestamp validi. Nessun ID di risorsa/sessione o corpo provider è pubblicato. Il precedente candidato 781c aveva cinque PASS e global RED: un ticker con underscore veniva rifiutato da un validatore di output troppo stretto. Dopo diagnosi separata e fix mirato nel sorgente 2ec7, la qualifica completa e sei nuove letture sono PASS; il precedente errore resta documentato, senza cambiare la grammatica degli ID richiesti dal chiamante o introdurre codice/URL/modi autenticati arbitrari.

[**Server e CLI 43 sono pubblici**](https://github.com/openagent-uno/openagent/releases/tag/v1.1.0-beta.43) dal sorgente `276704b2be1f403c9e2796e04c5c3e31530690c1`, con SDK 0.1.6 e 19 connector ufficiali. Le [157 fixture installate](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/product43-installed-2026-10-17.json), i 15 casi di acquisizione e il [normale installer pubblico server+CLI](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/product43-public-installer-2026-10-17.json) sono PASS, con HOME/TMPDIR predefiniti e versioni verificate. La [ricevuta lifecycle43](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/keyless-product-1.1.0b43-2026-10-17.json) registra tre connessioni keyless e **sei ulteriori letture effettive tramite workflow ordinari**, dopo SRP/certificato/Iroh: Parallel Fetch, Context7 query-docs e CoinGecko global prima e dopo un riavvio reale. ID delle tre connessioni conservati, sorgenti autorizzate al proprietario, sola lettura, disconnessione/tombstone/rimozione sorgenti e arresto dei processi QA sono verificati. Una sola submission per lettura; nessun modello, token o bypass diretto del runner/provider dal collaudo.

I byte e gli SHA del lifecycle43 misurano il **risultato del workflow**, non una risposta HTTP grezza. Questa API non espone la telemetria HTTP/tentativi del provider: tali osservazioni restano `null`; la policy a un tentativo proviene dalla qualifica SDK separata. Nessun contenuto provider, ID di risorsa/sessione, handle o profilo è pubblicato.

**App 20 è pubblicata**, con qualifica nativa del normale workflow e GUI Linux per le 19 card SDK16. Le precedenti prove SDK15/prodotto41/42/App19 restano storiche; nessuna di queste prove diventa accettazione delle tre nuove card Calendar/Outlook SDK17.

## Prove storiche SDK 15, prodotto41/42 e App19


Il sorgente [`7967195`](https://github.com/openagent-uno/openagent-tools/commit/7967195e9e45502c2d8b4f82414f7da780788045) è pubblicato come [**SDK 0.1.5**](https://github.com/openagent-uno/openagent-tools/releases/tag/connectors-v0.1.5), con **16 adapter ufficiali più Custom MCP**. Exa e Firecrawl espongono due strumenti di lettura ciascuno, tramite MCP ufficiale keyless. La **qualifica remota SDK è completata**: race, vet, vulnerabilità, sei piattaforme/dodici binari, adapter Python, smoke nativo e acquisizione da server 39. Gli **11 artefatti pubblici sono verificati tramite digest**, compreso il manifest letto senza autenticazione. La [ricevuta SDK](connector-keyless-0.1.5-qualification.json) conserva il legame fra sorgente e release. Anche [server e CLI 42 sono pubblici](https://github.com/openagent-uno/openagent/releases/tag/v1.1.0-beta.42): adottano SDK 0.1.5; il collaudo provider limitato effettuato su 41 e quello dell’installer 42 sono distinti. App 19 è ora [pubblicata per sei target nativi](https://github.com/openagent-uno/openagent-app/releases/tag/v1.1.0-beta.19); il [collaudo GUI Linux x64 con server 42](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/app19-server42-marketplace-2026-10-17.json) è PASS limitatamente al marketplace e ai controlli locali keyless, separato dalle chiamate provider. Gli altri target del runner SDK non sono dichiarati tutti eseguiti nativamente. La connessione conserva autorizzazione e isolamento locali; `auth=none` richiede un contratto esplicito senza token, con endpoint e strumenti compilati. Nessun fallback autenticato o a pagamento.

Il 17 ottobre sono riuscite quattro chiamate reali limitate tramite runner: Exa Search (681 ms, 323 byte), Fetch (982 ms, 1.376 byte), Firecrawl Search (1.544 ms, 1.306 byte) e Scrape (2.956 ms, 6.686 byte), tutte HTTP 200 e un solo tentativo. **La ricerca Exa prova il successo API, non la pertinenza**: la risposta non conteneva il marker OpenAgent. Queste prove SDK restano distinte dal successivo collaudo del prodotto.

La [ricevuta del percorso server/CLI 41](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/keyless-product-1.1.0b41-2026-10-17.json) registra due connessioni normali e **quattro ulteriori letture reali totali** tramite CLI certificata, Iroh/gateway e workflow autorizzati: Fetch Exa e Scrape Firecrawl prima e dopo un riavvio effettivo. Le connessioni hanno conservato gli stessi ID; disconnessione, tombstone disabilitate, rimozione delle sorgenti MCP e arresto dei processi QA sono verificati. Nessun token, consenso OAuth, LLM o chiamata diretta al runner nel collaudo prodotto. Il primo installer pubblico 41 è **RED per EXDEV** fra mount diversi; il normale recupero con lo stesso script/prefix e `TMPDIR` owned sul mount di installazione è **PASS**, senza qualificare un'installazione vergine fra filesystem diversi. Gli errori del solo harness sono conservati separatamente. Il successivo [server/CLI 42](https://github.com/openagent-uno/openagent/releases/tag/v1.1.0-beta.42) è pubblico: 149 fixture installate e 15 casi di acquisizione sono PASS, così come il [nuovo installer pubblico fra filesystem distinti](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/product42-public-installer-2026-10-17.json), senza workaround. Il codice provider è invariato; le chiamate reali restano prove effettuate su 41, non nuovi collaudi provider su 42. App 19 è pubblicata con 36 artefatti e sei target nativi qualificati. La [ricevuta nativa](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/app19-native-release-2026-10-17.json) conserva il fallimento originale dello stapling ARM e il successivo recupero riuscito; il [collaudo GUI App 19/server42](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/app19-server42-marketplace-2026-10-17.json) è PASS su Linux x64: 16 card ufficiali e 30 risultati registry nella stessa griglia, sei icone locali verificate, Connect/disable-enable/disconnect Exa e Firecrawl senza form credenziali o OAuth. Quattro screenshot reali sono stati revisionati; i due precedenti errori del solo harness e la pulizia sono documentati. Nessuna chiamata provider, modello, mock o source overlay. Electron hosted usa `--no-sandbox`: sicurezza sandbox e GUI Mac/Windows non sono qualificate. Non si stabiliscono copertura di tutti gli strumenti o parità ChatGPT.

“Interfaccia non stabilita da questo audit” significa ricerca ancora necessaria, non “il provider non ha API”. Le fonti primarie API/MCP sono state verificate per 32 nomi; le nuove ricerche rimangono separate dal codice implementato. Tutti gli altri nomi rimangono nel backlog esplicito del JSON. Un MCP configurabile dall’utente non viene contato automaticamente come connector ufficiale pronto.

## Sei ulteriori interfacce Popular: ricerca, non implementazione

La [ricevuta primaria del 17 ottobre](chatgpt-primary-interface-audit-2026-10-17.json) documenta Remote Desktop Commander (1), Flaim Fantasy (3), WPVibe (5), Windsor.ai (11), Upwork (14) e Granola (19). Restano tutti **non implementati/non qualificati** nel catalogo ufficiale. Granola, Windsor e Upwork documentano MCP OAuth con registrazione dinamica del client (DCR): per quel percorso non serve presumere una nuova app manuale OpenAgent, ma account, consenso e compatibilità del client vanno ancora qualificati. Il percorso GraphQL di Upwork ha registrazione/chiavi proprie, separata dal suo MCP. Remote Desktop Commander richiede anche agent e pairing; Flaim una lega autorizzata; WPVibe login e autorizzazione WordPress. DCR per questi ultimi tre non è stabilito dalle fonti correnti. Nessuno dei sei è una nuova lettura pubblica `auth=none` già pronta. Il JSON conserva le letture documentali non disponibili (WPVibe nella rilettura indipendente, Upwork403 e vecchia pagina Flaim404); non sono state eseguite registrazioni o chiamate MCP/API.

## Parallel Search, Context7 e CoinGecko: checkpoint SDK16 e prodotto43/App20

La [preparazione Parallel](parallel-search-preparation.md) conserva le tre richieste iniziali di soli metadati e le distingue dalle due letture effettivamente riuscite nel successivo SDK 16. Context7 espone due operazioni documentali; CoinGecko soltanto due template SDK compilati per dati pubblici. Nessun execute generico, account, wallet o fallback a pagamento è esposto. Tutti usano una connessione locale autorizzata con credenziale esplicita `none`.

Il catalogo SDK16 di questo checkpoint contiene 19 connector ufficiali; i conteggi della directory e la ricerca primaria di 32 nomi restano invariati. La qualifica SDK resta distinta dai successivi installer e sei workflow 43 riusciti; non qualifica automaticamente App 20. Nel JSON `historical_sdk15_checkpoint` conserva il precedente catalogo pubblico, lifecycle41/installer42 e accettazione App 19; `historical_sdk16_checkpoint` conserva questi artefatti; `published_catalog` conserva il checkpoint SDK17; la ricevuta SDK18 sopra identifica la nuova pubblicazione, senza riscrivere quella fotografia.

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
| 8 | [Outlook Email](https://chatgpt.com/plugins/plugin_connector_1p_6bcb5879c73c819196abc70016166099) | SDK 0.1.7/0.1.8 pubblicato: 9 tool typed; consenso reale Microsoft non qualificato | [API pubblica documentata](https://learn.microsoft.com/en-us/graph/api/resources/mail-api-overview?view=graph-rest-1.0) |
| 9 | [Supabase](https://chatgpt.com/plugins/plugin_asdk_app_69d3e5ee6a708191baa733f7b8931995) | SDK 0.1.8 pubblicato: 2 letture API typed, token manuale; QA reale e parità ChatGPT non qualificate | [MCP ufficiale documentato](https://supabase.com/docs/guides/ai-tools/mcp) |
| 10 | [Firecrawl](https://chatgpt.com/plugins/plugin_asdk_app_6a314a73f8ac819195b0d55e36b9c609) | Incluso SDK 0.1.6/server 43; Scrape/lifecycle41 e GUI19 restano prove storiche separate | [MCP keyless ufficiale](https://docs.firecrawl.dev/mcp-server/keyless) |
| 11 | [Windsor.ai](https://chatgpt.com/plugins/plugin_asdk_app_694a52cfaa3c819192bea84eaa254968) | Da implementare/qualificare | [MCP OAuth con DCR](https://mcp.windsor.ai/) |
| 12 | [Exa](https://chatgpt.com/plugins/plugin_asdk_app_69ea4ed2cf7c8191b742ef3622479ddd) | SDK 0.1.5/server 42 pubblici, fresh installer PASS; Fetch/lifecycle limitato su 41 PASS, App separata | [MCP keyless ufficiale](https://exa.ai/docs/get-started/exa-mcp) |
| 13 | [Render](https://chatgpt.com/plugins/plugin_asdk_app_6a624c56bfe081918f7544f7d58f6faf) | SDK 0.1.8 pubblicato: 2 letture API typed, token manuale; QA reale e parità ChatGPT non qualificate | [MCP ufficiale documentato](https://render.com/docs/mcp-server) |
| 14 | [Upwork](https://chatgpt.com/plugins/plugin_asdk_app_6a75165ed2d8819182548553aa4cb6d5) | Da implementare/qualificare | [MCP ufficiale](https://www.upwork.com/ai/mcp?trk=public_profile__reactions-text); [manifest vendor](https://github.com/upwork/upwork-agent-plugin/blob/master/mcp.json) |
| 15 | [Notion](https://chatgpt.com/plugins/plugin_asdk_app_69c18c28f1188191bf5b8445c4ab0a2e) | SDK 0.1.4 pubblicato: 8 tool; consenso comune pubblico, copertura strumenti e accettazione App separate | [REST API versionata](https://developers.notion.com/reference/versioning); [MCP ufficiale documentato](https://developers.notion.com/guides/mcp/overview) |
| 16 | [Slack](https://chatgpt.com/plugins/plugin_asdk_app_69a1d78e929881919bba0dbda1f6436d) | SDK 0.1.4 pubblico: 9 tool; [lifecycle QA limitato 16 ottobre PASS](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/slack-oauth-2026-10-16.json), distribuzione/common enrollment OFF | [Web API](https://docs.slack.dev/apis/); [MCP separato soggetto ad approvazione](https://docs.slack.dev/ai/slack-mcp-server/) |
| 17 | [Parallel Search](https://chatgpt.com/plugins/plugin_asdk_app_69fb9378663481919a68e8a2109644e5) | SDK 0.1.6/server 43 pubblici: 2 letture SDK e 2 Fetch workflow PASS; accettazione App distinta | [MCP ufficiale](https://docs.parallel.ai/integrations/mcp/search-mcp) |
| 18 | [Shopify](https://chatgpt.com/plugins/plugin_asdk_app_69e65c430b3081919aa4d962ab5d1698) | Adapter presente; common OAuth bloccato | [API pubblica documentata](https://shopify.dev/docs/api/admin-graphql/latest) |
| 19 | [Granola](https://chatgpt.com/plugins/plugin_asdk_app_697761cab6f48191b5ed345919a3ce8b) | Da implementare/qualificare | [MCP OAuth con DCR](https://docs.granola.ai/help-center/sharing/integrations/mcp) |
| 20 | [Klaviyo](https://chatgpt.com/plugins/plugin_asdk_app_694421e60cc88191a1e5bb4aa79950e4) | SDK 0.1.8 pubblicato: 2 letture API typed, token manuale; QA reale e parità ChatGPT non qualificate | [API pubblica documentata](https://developers.klaviyo.com/en/reference/api_overview) |
| 21 | [SentinelX](https://chatgpt.com/plugins/plugin_asdk_app_69f63e01766881919640f03b5e7912a5) | Da implementare/qualificare | Da verificare |
| 22 | [TinyFish](https://chatgpt.com/plugins/plugin_asdk_app_695325bae7348191b58ae9349a963d22) | Da implementare/qualificare | Da verificare |
| 23 | [Wispr Flow](https://chatgpt.com/plugins/plugin_asdk_app_6a5ae9736be0819199d06d61ac171080) | Da implementare/qualificare | Da verificare |
| 24 | [Canva](https://chatgpt.com/plugins/plugin_connector_68df33b1a2d081918778431a9cfca8ba) | SDK 0.1.8 pubblicato: 2 letture API typed, token manuale; QA reale e parità ChatGPT non qualificate | [API pubblica documentata](https://www.canva.dev/docs/apps/rest-apis/) |
| 25 | [Railway](https://chatgpt.com/plugins/plugin_asdk_app_6a502589384081919c5decf93496c9d1) | SDK 0.1.8 pubblicato: 2 letture API typed, token manuale; QA reale e parità ChatGPT non qualificate | [MCP ufficiale documentato](https://docs.railway.com/ai/mcp-server) |
| 26 | [Adspirer](https://chatgpt.com/plugins/plugin_asdk_app_69461dc91ee48191ae4a14eb9bde1c21) | Da implementare/qualificare | Da verificare |
| 27 | [Vercel](https://chatgpt.com/plugins/plugin_connector_690a90ec05c881918afb6a55dc9bbaa1) | SDK 0.1.8 pubblicato: 2 letture API typed, token manuale; QA reale e parità ChatGPT non qualificate | [MCP ufficiale documentato](https://vercel.com/docs/agent-resources/vercel-mcp) |
| 28 | [Otter.ai](https://chatgpt.com/plugins/plugin_asdk_app_695d84e2f06c8191861b9bac9b3fd53b) | Da implementare/qualificare | Da verificare |
| 29 | [GitLab (Beta)](https://chatgpt.com/plugins/plugin_connector_1p_5925693c1aa88191a4959257e60d0734) | SDK 0.1.8 pubblicato: 2 letture API typed, token manuale; QA reale e parità ChatGPT non qualificate | [MCP ufficiale documentato](https://docs.gitlab.com/user/model_context_protocol/mcp_server/) |
| 30 | [HubSpot](https://chatgpt.com/plugins/plugin_asdk_app_697acb8e53d88191bf7a79e62012ae14) | SDK 0.1.8 pubblicato: 2 letture API typed, token manuale; QA reale e parità ChatGPT non qualificate | [MCP ufficiale documentato](https://developers.hubspot.com/ai-tools/mcp) |
| 31 | [GSC Wizard](https://chatgpt.com/plugins/plugin_asdk_app_6a258ab1e0908191aa647c33299ad14c) | Da implementare/qualificare | Da verificare |
| 32 | [vidIQ](https://chatgpt.com/plugins/plugin_asdk_app_69dd11f3e50c8191b1ca48d03cf7e2ad) | Da implementare/qualificare | Da verificare |
| 33 | [Asana](https://chatgpt.com/plugins/plugin_asdk_app_69616780bd208191b4fb44ba44f72b61) | SDK 0.1.8 pubblicato: 2 letture API typed, token manuale; QA reale e parità ChatGPT non qualificate | [API pubblica documentata](https://developers.asana.com/docs/overview) |
| 34 | [Metricool](https://chatgpt.com/plugins/plugin_asdk_app_69d73fc8aa5c8191bec1583760b130c7) | Da implementare/qualificare | Da verificare |
| 35 | [Superhuman Mail](https://chatgpt.com/plugins/plugin_asdk_app_69a21e4058dc8191a6220fa911310d7b) | Da implementare/qualificare | Da verificare |
| 36 | [IOL invertironline](https://chatgpt.com/plugins/plugin_asdk_app_6a207f00eed0819181227b2ea257ff0b) | Da implementare/qualificare | Da verificare |
| 37 | [Fathom](https://chatgpt.com/plugins/plugin_asdk_app_69d88b99c5c481918e8da9225737e1e9) | SDK 0.1.8 pubblicato: 2 letture API typed, token manuale; QA reale e parità ChatGPT non qualificate | [Contratti API e fonti primarie](../packages/connectors/definitions/batch01/providers.json) |
| 38 | [Fireflies](https://chatgpt.com/plugins/plugin_connector_6912075cb358819187346bcafb601db8) | SDK 0.1.8 pubblicato: 2 letture API typed, token manuale; QA reale e parità ChatGPT non qualificate | [Contratti API e fonti primarie](../packages/connectors/definitions/batch01/providers.json) |
| 39 | [ClickUp](https://chatgpt.com/plugins/plugin_asdk_app_69431e6d26b88191b4029488aeb42f5b) | Adapter presente; consenso comune pubblico, qualifica delimitata | [API pubblica documentata](https://developer.clickup.com/) |
| 40 | [Interactive Brokers (IBKR)](https://chatgpt.com/plugins/plugin_asdk_app_69bc11db874881918718abaca20b68ce) | Da implementare/qualificare | Da verificare |
| 41 | [Todoist: To Do List & Calendar](https://chatgpt.com/plugins/plugin_asdk_app_6943b73823548191a9f9216c6790c453) | SDK 0.1.8 pubblicato: 2 letture API typed, token manuale; QA reale e parità ChatGPT non qualificate | [Contratti API e fonti primarie](../packages/connectors/definitions/batch01/providers.json) |
| 42 | [Opera Browser Connector](https://chatgpt.com/plugins/plugin_asdk_app_69d669e1d5c88191957786fbcd38b411) | Da implementare/qualificare | Da verificare |
| 43 | [Ahrefs](https://chatgpt.com/plugins/plugin_asdk_app_6966958473488191b775fdb667c52eab) | SDK 0.1.8 pubblicato: 2 letture API typed, token manuale; QA reale e parità ChatGPT non qualificate | [MCP commerciale con restrizioni di client](https://docs.ahrefs.com/en/mcp/docs/introduction); [API su piano commerciale](https://docs.ahrefs.com/en/api/docs/introduction) |
| 44 | [monday.com](https://chatgpt.com/plugins/plugin_connector_690aabb71bf481918b8d5b614ed3fd4c) | SDK 0.1.8 pubblicato: 2 letture API typed, token manuale; QA reale e parità ChatGPT non qualificate | [API pubblica documentata](https://developer.monday.com/api-reference/docs/basics) |
| 45 | [Tredict](https://chatgpt.com/plugins/plugin_asdk_app_69aef5b699a0819184512d57743fc1cd) | Da implementare/qualificare | Da verificare |
| 46 | [Webflow](https://chatgpt.com/plugins/plugin_asdk_app_6a0783a98c4c8191841404d786d4a4b9) | SDK 0.1.8 pubblicato: 2 letture API typed, token manuale; QA reale e parità ChatGPT non qualificate | [API pubblica documentata](https://developers.webflow.com/data/reference/rest-introduction) |
| 47 | [HYPD AI - Paid Ads & Analytics](https://chatgpt.com/plugins/plugin_asdk_app_6a3170ea7fc88191be6c0b9ff250a4b4) | Da implementare/qualificare | Da verificare |
| 48 | [SharePoint](https://chatgpt.com/plugins/plugin_connector_1p_dca009ae2c848191ae14df3a47c5e7fd) | SDK 0.1.8 pubblicato: 7 letture Graph; consenso reale Microsoft non qualificato | [API pubblica documentata](https://learn.microsoft.com/en-us/graph/api/resources/sharepoint?view=graph-rest-1.0) |
| 49 | [Floot](https://chatgpt.com/plugins/plugin_asdk_app_6a500d350f8c819194e30335a7b134af) | Da implementare/qualificare | Da verificare |
| 50 | [Quo](https://chatgpt.com/plugins/plugin_asdk_app_69e6af3297d88191b4925772c50df286) | SDK 0.1.8 pubblicato: 2 letture API typed, token manuale; QA reale e parità ChatGPT non qualificate | [Contratti API e fonti primarie](../packages/connectors/definitions/batch01/providers.json) |

## Confini già noti

- **Google Drive e Gmail:** il codice esiste; verifica OAuth, scope e requisiti di sicurezza Google restano distinti dalla disponibilità del codice.
- **ClickUp:** consenso comune pubblico abilitato il 17 ottobre; adapter e percorso common OAuth hanno una qualifica reale delimitata, descritta nel [checkpoint del broker](../deploy/connector-auth/qualification-2026-10-14.md). Non estende l’accettazione ad altri provider.
- **Shopify:** adapter presente, iscrizione common ancora disattivata finché privacy, webhook e ciclo credenziali sullo stesso negozio con due server non sono qualificati.
- **GitHub e Notion:** adapter pubblicati in SDK 0.1.4 e consenso comune pubblico abilitato il 17 ottobre. I collaudi limitati già citati restano separati dalla copertura di tutti gli strumenti e dall’accettazione delle operazioni nella App nativa. Il checkpoint pubblico del broker non aggiunge un nuovo collaudo OAuth.
- **Slack:** SDK 0.1.4 pubblica nove tool Web API typed mantenendo l’ID `slack-import`, provider `slack_import` e capability Social. La [ricevuta QA del 16 ottobre](https://github.com/openagent-uno/openagent/blob/main/docs/qualification/slack-oauth-2026-10-16.json) conserva consenso, letture autorizzate, messaggio create/read/delete con pulizia verificata, rinnovo dopo recupero esplicito, lettura dopo restart e disconnessione locale. La precedente ricevuta descrive correttamente il candidato allora non pubblicato e rimane immutata; **distribuzione pubblica e common enrollment sono ancora OFF**. Non sono qualificati tutti i tool, la App nativa o il [MCP ufficiale](https://docs.slack.dev/ai/slack-mcp-server/), che richiede approvazione separata. History/replies restano limitati a 15 messaggi senza retry automatico, rispettando il [confine delle app commerciali non Marketplace](https://docs.slack.dev/changelog/2025/05/29/rate-limit-changes-for-non-marketplace-apps/).
- **Ahrefs:** [MCP commerciale](https://docs.ahrefs.com/en/mcp/docs/introduction) e [API pubblica](https://docs.ahrefs.com/en/api/docs/introduction) hanno condizioni differenti. La documentazione vieta bridge/script/client HTTP autonomi sull’MCP esterno: usare l’API supportata o ottenere autorizzazione esplicita.
- **Atlassian:** nove tool Jira REST pubblicati dal SDK 0.1.4 e inclusi anche nel SDK 0.1.8, con sito `cloud_id` scelto dall’host e mai dagli argomenti del modello. App creata, callback e due scope classici read/write salvati; custodia del segreto e consenso reale per il sito restano pendenti. La qualifica delle API non estende l’accettazione a Confluence o al [MCP Rovo](https://support.atlassian.com/atlassian-ai-gateway/docs/get-started-with-the-atlassian-remote-mcp-server/), che conserva condizioni e crediti separati.
- **Outlook Email e SharePoint:** le API Microsoft Graph documentate non sono equivalenti a un accesso generico IMAP o all’intera esperienza ChatGPT.

## Tre integrazioni keyless ora pubblicate nel SDK

La precedente ricerca ha portato a Parallel Search, Context7 e CoinGecko nel SDK 0.1.6 pubblico. Parallel segue la posizione editoriale 17 di Popular; gli altri due compaiono nelle altre categorie senza posizione Popular registrata. Due letture SDK per ciascuno e sei ulteriori letture workflow 43 sono PASS; App 20 e copertura più ampia restano separate.

| Provider | Superficie pubblicata nel SDK | Autenticazione e limiti |
| --- | --- | --- |
| [Parallel Search](https://docs.parallel.ai/integrations/mcp/search-mcp) | `files.parallel.search` / `files.parallel.fetch` | Endpoint ufficiale fisso; credenziale `none`, query/URL limitati. Gli argomenti `session_id` e `model_name` sono omessi; nessuna stabilità di sessione o modalità autenticata è promessa. |
| [Context7](https://github.com/upstash/context7/blob/master/packages/mcp/README.md) | `files.context7.resolve_library` / `files.context7.query_docs` | Uso base senza chiave; ID effettivamente restituito e poi usato nel collaudo. Quote anonime; repository privati, indicizzazione e modalità autenticate esclusi. |
| [CoinGecko](https://docs.coingecko.com/ai-integration/mcp-server) | `files.coingecko.price` / `files.coingecko.global` | Template SDK compilati verso endpoint fisso, nessun execute/codice/URL/opzioni dal modello; un tentativo. Quote condivise e funzioni a pagamento restano fuori dalla qualifica. |

Il trasporto keyless non sostituisce il binding autorizzato locale. Il [setup generale Blockscout](https://github.com/blockscout/mcp-server) richiede una chiave PRO dal Developer Portal anche sul piano gratuito: rimane fuori da questa coorte senza registrazioni.

## Catalogo OpenAgent fuori dal confronto dei soli nomi Popular

Il JSON conserva tutte le voci del catalogo sorgente, anche se il relativo nome non compare nella fotografia pubblica. Gmail, Postiz, Pipeboard Ads, Replio, BillingBear, Google Analytics e IMAP Email non devono essere scartati solo perché non sono nelle prime 50. Una corrispondenza nominale con una card non prova identità del provider né parità delle funzioni.

## Lavoro necessario per coprire tutte le voci

1. Conservare questa fotografia come backlog completo delle card osservate e risolvere gli omonimi tramite ID pubblico prima di creare registrazioni.
2. SDK 0.1.8 è pubblico con 114 profili ufficiali; Server/CLI 44 e App 21 restano i prodotti pubblici su SDK 0.1.7. I sei workflow provider/restart/disconnect PASS su 43 restano prove storiche delimitate; il collaudo GUI Linux x64 App 19/server42 e i controlli locali keyless sono PASS, distinti dai workflow provider limitati già passati su 41 e dal nuovo installer 42. Qualificare separatamente GUI degli altri sistemi, sicurezza sandbox e operazioni provider nella App. Per gli adapter già pubblicati, completare i gate ancora aperti per strumenti, App nativa e consenso generale dei provider rimasti chiusi; il consenso pubblico ClickUp/GitHub/Notion non estende l’accettazione agli altri.
3. Per ogni voce verificare prima fonte ufficiale, condizioni commerciali, autenticazione e disponibilità fuori da ChatGPT. Le interfacce sconosciute restano esplicitamente da ricercare.
4. Riutilizzare un MCP ufficiale quando trasporto, autenticazione e condizioni sono compatibili; altrimenti costruire un adapter API condiviso. Un servizio chiuso o riservato a partner richiede un accordo, non un endpoint inventato.
5. Conservare token ed esecuzione nei server locali; usare il broker per i soli passaggi OAuth ammessi dal provider. Non trasferire cookie, endpoint privati o segreti di ChatGPT.
6. Qualificare discovery, lettura, scrittura autorizzata quando prevista, rinnovo se applicabile, riavvio, disconnessione e isolamento dei permessi. Registrazione, codice o catalogo da soli non sono prova di funzionamento.

L’inventario conserva l’intero backlog e la mappa delle fonti. La rilevazione originale della directory non richiedeva build o chiamate ai dati dei provider; i successivi risultati del candidato e delle registrazioni sono riportati separatamente nel checkpoint. Non vengono aggiunte automaticamente migliaia di integrazioni, attivati provider o dichiarata parità con la directory.
