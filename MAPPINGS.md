# Attribute Mappings

## Default mappings

The `attribute_mapping` section in the YAML config maps LDAP attribute names to vCard property paths. Paths use dot notation for sub-properties and typed values.

| LDAP attribute | VCF/CardDAV entry | Description |
|---|---|---|
| `uid` | `UID` | Unique identifier |
| `cn` | `FN` | Common name (set to `<displayName> (<uid>)` when UID is present) |
| `displayName` | `FN` | Display name (always set to the original full name) |
| `sn` | `N` (family) | Surname / family name (falls back to `?` if empty) |
| `givenName` | `N` (given) | Given / first name |
| `middleName` | `N` (additional) | Middle name |
| `namePrefix` | `N` (prefix) | Honorific prefix (e.g. "Dr.", "Mr.") |
| `nameSuffix` | `N` (suffix) | Honorific suffix (e.g. "Jr.", "PhD") |
| `nickName` | `NICKNAME` | Nickname |
| `phoneticFirstName` | `X-PHONETIC-FIRST-NAME` | Phonetic first name pronunciation |
| `phoneticLastName` | `X-PHONETIC-LAST-NAME` | Phonetic last name pronunciation |
| `mail` | `EMAIL` | All email addresses |
| `workEmail` | `EMAIL;TYPE=WORK` | Work email addresses |
| `homeEmail` | `EMAIL;TYPE=HOME` | Home email addresses |
| `telephoneNumber` | `TEL` | All phone numbers |
| `mobile` | `TEL;TYPE=CELL` | Mobile phone numbers |
| `homePhone` | `TEL;TYPE=HOME` | Home phone numbers |
| `workPhone` | `TEL;TYPE=WORK` | Work phone numbers |
| `facsimileTelephoneNumber` | `TEL;TYPE=FAX` | Fax numbers |
| `pager` | `TEL;TYPE=PAGER` | Pager numbers |
| `title` | `TITLE` | Job title |
| `o` | `ORG` (1st component) | Organization name |
| `ou` | `ORG` (2nd component) | Department |
| `labeledURI` | `URL` | Website URL |
| `street` | `ADR` (street) | Street address |
| `l` | `ADR` (city) | City |
| `st` | `ADR` (region) | State / region |
| `postalCode` | `ADR` (code) | Postal code |
| `c` | `ADR` (country) | Country |
| `businessCategory` | `CATEGORIES` | Contact categories / tags |
| `description` | `NOTE` | Notes |
| `birthday` | `BDAY` | Birthday |
| `jpegPhoto` | `PHOTO` | Contact photo (base64-encoded if binary) |
| `rev` | `REV` | Last-modified timestamp |
| `createdByApplication` | `PRODID` | Application that created the vCard |

## Automatic mappings

The following mappings are applied automatically and require no configuration.

### Related persons

vCard `RELATED` properties are mapped to custom LDAP attributes based on their TYPE:

| VCF/CardDAV entry | LDAP attribute | Description |
|---|---|---|
| `RELATED;TYPE=spouse` | `relatedSpouse` | Spouse |
| `RELATED;TYPE=assistant` | `relatedAssistant` | Assistant |
| `RELATED;TYPE=co-worker` | `relatedCoWorker` | Co-worker |
| `RELATED` (no type) | `relatedPerson` | Related person (untyped) |

Any RELATED TYPE is supported — the attribute name is `related<Type>` in PascalCase.

### Custom-labeled properties (X-ABLABEL)

Some CardDAV clients (Android, iOS) use vCard grouping with `X-ABLABEL` to attach custom labels to phone numbers, email addresses, and postal addresses:

```
ITEM1.X-ABLABEL:Vacation Home
ITEM1.TEL:+43 677 62951924
```

These grouped values are automatically included in the collective attribute (e.g. `telephoneNumber`) and additionally mapped to a custom attribute based on the label in PascalCase:

| VCF/CardDAV entry | Label | LDAP attribute |
|---|---|---|
| `TEL` | Mobile | `customTelephoneMobile` |
| `TEL` | Work Mobile | `customTelephoneWorkMobile` |
| `EMAIL` | Office | `customEmailOffice` |
| `ADR` | Vacation Home | `customAddressVacationHome` |

### Unmapped properties

Any vCard property not covered by the attribute mapping, related persons, or custom labels is automatically stored as `vcfUnmapped<PropertyName>` in PascalCase. For example, `X-CUSTOM-FIELD` becomes `vcfUnmappedXCustomField`. This ensures no contact data is silently dropped.

## Customizing

The default mapping can be overridden via the `attribute_mapping` section in the YAML config file. Attribute mapping is not configurable via environment variables.

```yaml
attribute_mapping:
  cn: [fn]
  sn: [n.family]
  mail: [email]
  telephoneNumber: [tel]
```

See [config.example.yaml](config.example.yaml) for the full default mapping.
