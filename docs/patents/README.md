# MRML worldwide patent-awareness policy

This directory records automated technical screening and triage. It is not a
legal opinion, freedom-to-operate search, validity analysis, or infringement
conclusion. No result proves MRML is patent-free; no listing proves
infringement.

Historical review entries retain their original repository paths. Resolve old
`crates/...` references through the canonical
[source-path migration map](PATH_MIGRATION.md) instead of rewriting the review
record.

## Global scope

Patent rights are territorial. The PCT is an international filing/search route;
WIPO does not grant a worldwide patent. Review therefore has two layers:

1. discover publications and families worldwide through PATENTSCOPE,
   Espacenet/INPADOC, classifications, citations, standards declarations, and
   national/regional databases;
2. for every serious family, compare claims and independently verify each
   material national or regional member in its authoritative register.

Use these operational tiers:

- **Tier 1, mandatory deep review:** Canada, United States, EPO/European
  rights, United Kingdom, China, Japan, South Korea, India, Australia, Brazil,
  and every jurisdiction where MRML is materially developed, distributed,
  hosted, manufactured, imported, sold, or deployed.
- **Tier 2, family-driven review:** every other national or regional system in
  which a serious family has an apparently live member, including ARIPO,
  Eurasian, GCC, and OAPI routes where applicable.
- **Tier 3, worldwide discovery:** publications, PCT applications, citations,
  and family records used to find counterparts and prior art. A discovery hit
  is not an enforceable right without territorial verification.

A legal reviewer must set the final commercial-country list before release.
Global screening must disclose language, database, date, coverage, translation,
and status limitations rather than imply every record was searched.

## Required method

Inventory implemented code, not roadmap aspirations. Prioritize codecs, GPU
and device virtualization, inference/training optimizations, quantization,
compression, cryptography, hardware security, storage/network protocols, and
novel compiler work. Search the mechanism, algorithm, data flow, state machine,
memory layout, synchronization, and hardware interaction; use CPC/IPC and
multilingual synonyms where useful.

For every serious candidate:

1. identify relevant independent and material dependent claims;
2. decompose each claim into required limitations and compare every limitation
   with named MRML files/functions;
3. identify the family/priority chain without assuming identical claims;
4. verify grant, prosecution, opposition/re-examination, revocation, lapse,
   fees, ownership, term, adjustments/extensions, and current status for each
   material territorial right in an authoritative register;
5. record `ACTIVE`, `PENDING`, `EXPIRED`, `LAPSED`, `ABANDONED`, `CANCELLED`, or
   `UNKNOWN`, plus separate `SEARCH CONFIDENCE`, `TECHNICAL OVERLAP`, and
   `LEGAL STATUS CONFIDENCE` values;
6. record technically apparent alternatives without deleting code or copying
   implementation details from the patent.

Applications are not issued enforceable patents. Publication, grant, and
current enforceability are distinct. Family members may have different claims,
owners, terms, and outcomes.

## Patent-safe design preference

Future substantial code must prefer, in order:

1. ordinary, long-established mechanisms with no targeted review trigger;
2. a clearly non-overlapping design documented against relevant claim
   limitations;
3. mechanisms whose relevant rights are authoritatively verified expired,
   lapsed, abandoned, or cancelled in all material territories;
4. mechanisms covered for MRML's exact use and distribution by a verified
   royalty-free patent grant.

For a royalty-free option, preserve the license text/reference and verify
covered patents/claims, specification and version, territories, beneficiaries,
field of use, making/using/selling/importing/distribution rights, sublicensing
or downstream coverage, reciprocity, defensive suspension, termination,
attribution/notice, patent-pool interaction, and compatibility with CC0 and
MRML distribution. "Royalty-free" does not necessarily mean unconditional,
irrevocable, worldwide, transferable, or risk-free.

If none of those paths can be established, mark the mechanism for targeted
professional review or select a documented design-around. Do not silently add
it, invent a clearance result, automatically delete existing code, or degrade
MRML merely because of speculative similarity.

## Sources and standards

Start discovery with [WIPO PATENTSCOPE](https://patentscope.wipo.int/) and the
[WIPO Patent Register Portal](https://www.wipo.int/en/web/wipo-inspire/patent-register-portal).
Use the [EPO Register](https://register.epo.org/) for European proceedings and
national registers for validations/national rights. Use CIPO, USPTO, UKIPO,
CNIPA, J-PlatPat/JPO, KIPRIS/KIPO, IP India, AusPat/IP Australia, INPI Brazil,
and the relevant issuing office for every material right. Aggregators and
machine translations assist discovery but do not replace official verification.

For standards, check current IPR policies and declarations from relevant SDOs
(including IETF, IEEE, ETSI, ITU, ISO/IEC, and AOMedia), pools, and the WIPO SEP
collection. A declaration is not proof of essentiality, validity, infringement,
or license availability. Record the exact license and conditions separately.

## Repository rules

- Use `PATENT-REVIEW: <mechanism>` sparingly; keep analysis here.
- AI generation, independent creation, open source, standards compliance, and
  CC0 do not establish patent clearance.
- Do not derive implementation code from patents or paste specification prose.
- Keep privileged advice, licensing negotiations, personal data, and
  confidential material outside this public repository.
- For substantial commits report `Patent review: NOT_TRIGGERED` or
  `Patent review: TRIGGERED`, its reason, and the review-log entry.
- Move rights between registers only after verification; retain history/date.

Candidate records must include jurisdiction, publication/application/grant
numbers and kind codes, family/priority, owner, status/source/date, term, MRML
source, relevant claims, limitation comparison, alternatives, all three
confidence fields, reviewer/date, license conditions if any, and the automated
screening disclaimer.
