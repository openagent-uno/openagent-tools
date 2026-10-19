# Broker SDK18 image checkpoint — 19 October 2026

The image-only rollout passed at **07:39:51 UTC**, using the public SDK
**0.1.8** authentication binary from Tools
`5a7dea3ec5edf183545ea703538d56b208069250`. The
[sanitized receipt](qualification-2026-10-19.json) records the image, binary,
scan and protected-evidence digests.

The new manifest is
`sha256:fc7c3ceba9f9db10746d8a9653245d0aa572aa370f58f50055a12fcb59166b19`.
Assembly retained the four parent layers and appended only `/connector-auth`;
the runtime configuration was preserved. All five compressed layer hashes and
uncompressed diff IDs were verified. No Go compilation or inherited signature
claim was involved. Upload used the manifest digest without writing a tag.

Trivy **0.72.0** returned exit 0 with zero findings under the normal
`vuln,secret`, `HIGH,CRITICAL`, `ignore-unfixed` policy, with no added exceptions.
The initial pure OCI archive was rejected by the scanner's input format; a
Docker-save compatibility manifest was added without changing the image,
configuration or layer bytes. The single authorized scan retry passed. The raw
report remains protected; its digest and policy are in the receipt.

Fresh compare-and-swap replaced only the image. One Recreate writer became
Ready without restart; HTTPS health and readiness returned **200**, and an
unsigned protected transaction request returned **401**. Provider bytes remained
unchanged: **ClickUp, GitHub and Notion** only. The metadata volume, event-key
reference and Secret mounts were preserved; no metadata was restored. Temporary
scan/transport processes were closed and all four owned systemd units were
absent afterward.

This step made **zero provider API calls** and obtained **no new grants**.
Google and Microsoft configuration, Secret mounting, consent and receiving-host
acceptance remain separate work; this checkpoint does not activate them.

`kustomization.yaml` now pins this image. Its checked-in base still generates
`providers.json=[]` and uses bootstrap health readiness: it is not a copy of the
live three-provider overlay. Do not apply the base as a production configuration
replacement. Preserve the current provider overlay independently.
