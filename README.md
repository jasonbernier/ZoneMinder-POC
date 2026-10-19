### Original Advisory
https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-m896-3fc6-2jf5
### Summary
ZoneMinder 1.38.4 has a missing-authorization vulnerability in its Config API.
Any authenticated, enabled, API-enabled user—including an account with
`System=None`—can retrieve effective configuration values loaded from
`zm.conf` and `conf.d`, including the plaintext `ZM_DB_PASS` database password.

This is a high-severity credential-disclosure vulnerability. If the database is
reachable with the disclosed credentials, a low-privileged ZoneMinder user may
be able to read or modify surveillance metadata, configuration, events, and
stored authentication material. I confirmed the disclosure against a local
ZoneMinder 1.38.4 instance.

### Details
The global API controller authenticates the caller, validates the access token,
and verifies that the user is enabled and API-enabled:

- `web/api/app/Controller/AppController.php:61-159`

Resource authorization is left to each controller. The Config controller's read
actions do not perform a `System` permission check:

- `ConfigsController::index()` reads all Config rows and merges/appends values
  from global `$zm_config`: `web/api/app/Controller/ConfigsController.php:24-51`.
- `ConfigsController::view()` returns the effective `$zm_config` value:
  `ConfigsController.php:61-75`.
- `ConfigsController::viewByName()` returns any named effective configuration
  value: `ConfigsController.php:77-97`.

The same controller requires `System=Edit` for the `edit()` and `delete()`
actions at lines 106-156. The missing read check is therefore inconsistent with
the controller's mutation authorization and the normal web Options permission
model.

`$zm_config` is populated from the main ZoneMinder configuration and readable
`conf.d/*.conf` files, then merged with database Config rows:

- `web/includes/config.php.in:191-259`
- `web/includes/config.php.in:299-317`

The file-backed configuration includes `ZM_DB_HOST`, `ZM_DB_NAME`, `ZM_DB_USER`,
and `ZM_DB_PASS` (`zm.conf.in:42-51`). The password is used directly for the PDO
database connection at `web/includes/database.php:59-61`.

Although the Config table has a `Private` attribute, none of these read actions
uses it to redact private values. File-backed secrets are also appended to the
index response, so filtering only database rows would not fully fix the issue.

There is a secondary secret-spill path at
`web/api/app/Controller/ConfigsController.php:86`: requesting an unknown name
causes `print_r($zm_config, true)` to be written to the ZoneMinder log. This may
copy the complete effective configuration into local logs and downstream log
collectors.

The issue was dynamically confirmed in 1.38.4. The same controller pattern is
also present in the reviewed 1.36.35 source, but I did not dynamically test every
intervening release.

### PoC
1. Enable `OPT_USE_API` and normal ZoneMinder authentication.
2. Configure `AUTH_HASH_SECRET` so API v2 access tokens can be issued.
3. Create an enabled test user with `APIEnabled` enabled and `System=None`.
   Other area permissions may also be set to `None`.
4. Ensure `ZM_DB_PASS` has a nonempty test value.

Obtain a low-privileged access token

```bash
curl -sS -X POST \
  -d 'user=lowpriv_api_user&pass=REDACTED_PASSWORD' \
  'https://zoneminder.example/zm/api/host/login.json'
```

The response contains an `access_token`. Use the access token—not the refresh
token—in the following request.

#### Retrieve `ZM_DB_PASS`

```bash
curl -sS --get \
  --data-urlencode 'token=REDACTED_ACCESS_TOKEN' \
  'https://zoneminder.example/zm/api/configs/viewByName/ZM_DB_PASS.json'
```

On the affected version, the server returns HTTP 200 and the effective database
password in the JSON `Value` field. Example with the secret removed:

```json
{
  "config": {
    "Value": "[REDACTED DATABASE PASSWORD]"
  }
}
```

The broader configuration can also be retrieved through:

```bash
curl -sS --get \
  --data-urlencode 'token=REDACTED_ACCESS_TOKEN' \
  'https://zoneminder.example/zm/api/configs.json'
```



### Impact
This is an authenticated sensitive-information disclosure caused by missing
resource authorization. Every ZoneMinder deployment running an affected version
with an enabled low-privileged API account is impacted.

The direct impact is disclosure of the effective database password and other
deployment-specific values from `zm.conf`, `conf.d`, and the Config table. The
attacker needs only a valid API-enabled ZoneMinder account; no System permission
or administrative role is required.

If the ZoneMinder database is reachable from the attacker and the disclosed
credential is accepted, follow-on impact may include:

- reading monitor, event, zone, user, and operational metadata;
- obtaining stored user authentication material for offline attack;
- altering recording or detection configuration;
- modifying or destroying surveillance and evidence metadata; and
- disrupting ZoneMinder by corrupting or deleting database records.

The precise follow-on impact depends on database network exposure and the
privileges assigned to the ZoneMinder database account. The plaintext secret
disclosure itself does not depend on database reachability.

Recommended remediation is to add deny-by-default authorization to all Config
read actions, expose only a strict allowlist of non-sensitive metadata, return a
fixed redacted placeholder instead of secret values even to administrators, and
remove the full `$zm_config` error logging. Users should be advised to rotate
credentials that may have been exposed through this API.
