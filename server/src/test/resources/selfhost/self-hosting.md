# Self-hosting andvari

Test fixture for the /selfhost route (the REAL guide is docs/self-hosting.md, bundled by
server/build.gradle.kts processResources — this fixture shadows it on the TEST classpath only).

<script>alert("must-be-escaped")</script>

- run `bringup.sh` once
- point any andvari app at **your origin**
- docs: [example](https://example.com/docs)

```bash
docker compose up -d
```
