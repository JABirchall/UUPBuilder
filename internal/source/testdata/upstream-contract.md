# Sanitized upstream contract observations

## Rate-limit wrapper reviewed 2026-10-29

The user supplied the limiter implementation and requested review of the
[JSON get.php wrapper at c82a95ae6377743f2712ac0bd060e673f4478b0c](https://git.uupdump.net/uup-dump/json-api/src/commit/c82a95ae6377743f2712ac0bd060e673f4478b0c/get.php).
The wrapper uses default limiter arguments and hashes the lowercase
update/language/edition tuple. Metadata-only `noLinks=1` requests skip the
rate-limit rejection. The limiter runs before that check, so such requests
can still update the per-IP resource/timestamp. The supplied defaults reject
resource changes for 10 seconds and repeats for 1 second; rejected repeats
update the timestamp, while rejected resource changes do not.

U01's deterministic tests model those state transitions and the wrapper's
exemption. Metadata-only calls use shared admission without the interval;
subsequent link-bearing calls wait at least 10.25 seconds from the previous
get.php attempt completing. Retries and recomposed clients share the same
service state. CDN Retry-After remains separate. This conservative client
policy cannot reserve an IP shared with other applications.

## Earlier source observations

Observed 2026-10-28 against `https://api.uupdump.net/`. These observations are
API evidence only. No payload URL, signature, credential, native conversion or
live semantic app inventory is retained here.

Primary source pinned by the JSON API repository's API submodule:

- [JSON wrapper](https://git.uupdump.net/uup-dump/json-api/raw/branch/master/listeditions.php)
- [Edition enumeration at 1c942f52d37bb8dadeae5b5eeca2900ecb1fa1d1](https://git.uupdump.net/uup-dump/api/src/commit/1c942f52d37bb8dadeae5b5eeca2900ecb1fa1d1/listeditions.php)
- [File and app resolution at the same commit](https://git.uupdump.net/uup-dump/api/src/commit/1c942f52d37bb8dadeae5b5eeca2900ecb1fa1d1/get.php)
- [JSON API parameter documentation](https://git.uupdump.net/uup-dump/json-api/src/branch/master)

Edition enumeration excludes LXP/FOD and otherwise advertises existing pack
keys. The JSON wrapper forwards that list. APP and APP_MOMENT require an
existing language pack key; missing combinations return UNSUPPORTED_COMBINATION.
APP includes APP_MOMENT when both exist. Selector or payload names do not
establish app family identities, dependencies, licenses or customization phase.
The noLinks path returns null download UUIDs and URLs; online refresh uses the
same exact source revision and selectors.

The bounded representative edition probes found neither app selector:

| Source UUID | Build | Architecture | Language |
| --- | --- | --- | --- |
| a1b78728-530f-443f-b672-d742e7c14bcb | 22000.1 | arm64 | en-us |
| b761d9de-8997-4056-ac72-25aefbe93548 | 26300.9807 | amd64 | en-us |
| 3d68645c-e4c6-4d51-8858-6421e46cb0bb | 26100.1 | amd64 | en-us |
| 8bb7f81c-c236-456c-92ca-1f70baf26f35 | 26100.1882 | amd64 | en-us |

These combinations do not advertise separate app sets; app-set success remains
unverified. The resolver retains target choices and requests source-specific
app metadata rather than inventing selectable families or declaring apps absent.

Real PROFESSIONAL noLinks-to-online refresh matched 46/46 frozen identities for
22000.1 arm64 and 96/96 for 26300.9807 amd64. The first current-source live run
failed with the sanitized message `catalog link refresh failed`; its original
API code was not recorded, so its cause is unknown. A repeat of that same source
passed. The initial failure remains evidence of an unsuccessful observation.
The final combined catalog/source live command again passed legacy refresh but
failed current-source refresh with HTTP 429, USER_RATE_LIMITED. That failure is
retained; no further live requests were made to replace it with a successful run.

Native metadata discovery/providers, post-materialization provisioned-app
inspection and conversion evidence remain implementation gaps outside D3's
deterministic orchestration ports.
