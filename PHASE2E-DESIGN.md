# Cevrixa Phase 2E — Source Correlation (Design)

**Status:** Design document. No implementation yet.
**Depends on:** Phase 0, 1, 2A, 2B, 2C, 2D
**Scope:** Evidence → Provenance → Correlation

---

## 1. Tujuan

Phase 2E menambahkan lapisan **correlation** yang menggabungkan informasi
vulnerability dari beberapa source menjadi satu representasi evidence-aware,
tanpa menghilangkan provenance source asli.

Phase 2E **tidak** membuat keputusan `affected` / `not_affected`. Itu adalah
tugas Phase 3 (Detection Engine). Phase 2E hanya:

```
Evidence  →  Provenance  →  Correlation
```

Prinsip yang dipegang:

- Setiap nilai penting harus bisa dilacak ke source asalnya.
- Jika dua source memberi nilai berbeda untuk field yang seharusnya tunggal,
  perbedaan itu **harus terlihat** sebagai conflict, bukan diam-diam dipilih.
- Source yang berbeda tidak dianggap sebagai "yang selalu benar".

---

## 2. Konsep yang Sudah Ada (Audit Aktual)

### 2.1 Domain model

`domain.Vulnerability` sudah kaya:

    ID, Source, SourceIdentifier, Status, Aliases, Summary, Details,
    Published, Modified, References, Applicability, PackageApplicability

- `Applicability []ApplicabilityNode` — dari NVD (CPE tree)
- `PackageApplicability []PackageApplicability` — dari OSV (package ranges)
- `Aliases []string` — sudah ada, siap dipakai untuk correlation

`domain.Enrichment`:

    Source, Status, Summary, Mitigation, Confidence,
    PoCURL, PatchCommitURL, Weaknesses, References, Attribution, Risk

- `Enrichment.Source` adalah field, bukan konstanta → source-agnostic.
- `Risk` (Severity/CVSS/CVSSVersion/KEV/EPSS/EPSSPercentile) saat ini hanya
  diisi oleh DBCVE, tetapi strukturnya memungkinkan enricher lain mengisinya.

### 2.2 Source abstraction

- `VulnerabilitySource` — `List(ctx, Query) (Result, error)`
- `VulnerabilityEnricher` — `Enrich(ctx, vulnID) (Enrichment, error)`

Keduanya canonical; schema adapter tidak bocor.

### 2.3 Yang belum ada

- Tipe `Evidence` (per-field provenance)
- Tipe `Conflict`
- Tipe `CorrelatedVulnerability`
- Package `internal/correlate/`
- `Enrichment.VulnerabilityID` (gap kecil dari Phase 2D)

---

## 3. Non-Goals (Phase 2E)

Phase 2E secara sadar **tidak** melakukan:

- Detection decision (`affected` / `not_affected`)
- Confidence scoring atau weighting
- Semantic version-range conflict
- CPE/PURL resolution
- Persistence, caching, snapshot
- Network loading di correlation layer
- CLI integration untuk `detect` (masih skeleton)
- Exploit / PoC execution / payload / scanning

---

## 4. Arsitektur

```
  []domain.Vulnerability           []domain.Enrichment
           │                                │
           └──────────────┬─────────────────┘
                          ▼
              ┌───────────────────────┐
              │   internal/correlate  │
              │                       │
              │  identity.Group()     │  → grup berdasarkan ID ∪ Aliases
              │  collect.Evidence()   │  → []Evidence per grup
              │  conflict.Detect()    │  → []Conflict per grup
              └───────────┬───────────┘
                          ▼
        []domain.CorrelatedVulnerability
```

Tidak ada I/O. Tidak ada state. Semua pure function.

---

## 5. Model Data

### 5.1 `Evidence`

Evidence = satu potongan informasi, dengan provenance.

```go
type EvidenceKind string

const (
    EvidenceKindAlias          EvidenceKind = "alias"
    EvidenceKindApplicability  EvidenceKind = "applicability"
    EvidenceKindPackageRange   EvidenceKind = "package_range"
    EvidenceKindStatus         EvidenceKind = "status"
    EvidenceKindSeverity       EvidenceKind = "severity"
    EvidenceKindCVSS           EvidenceKind = "cvss"
    EvidenceKindCVSSVersion    EvidenceKind = "cvss_version"
    EvidenceKindKEV            EvidenceKind = "kev"
    EvidenceKindEPSS           EvidenceKind = "epss"
    EvidenceKindEPSSPercentile EvidenceKind = "epss_percentile"
    EvidenceKindMitigation     EvidenceKind = "mitigation"
    EvidenceKindPoC            EvidenceKind = "poc"
    EvidenceKindPatch          EvidenceKind = "patch"
    EvidenceKindReference      EvidenceKind = "reference"
    EvidenceKindWeakness       EvidenceKind = "weakness"
)

type Evidence struct {
    Kind   EvidenceKind
    Source string

    // Value adalah representasi string kanonik untuk evidence scalar.
    // Contoh: severity → "CRITICAL", cvss → "9.8", kev → "true".
    // Kosong untuk evidence terstruktur.
    Value string

    // Salah satu field berikut diisi sesuai Kind.
    Reference     *Reference
    Range         *PackageRange
    Applicability *ApplicabilityNode
}
```

**Kenapa struct tunggal, bukan interface:** serializable, comparable, mudah
dipakai detection engine, tidak butuh reflection.

**Kenapa `Value string`:** menghindari `any`, menghindari union type,
menghindari JSON instability. Konversi kanonik:
- `float64` → `strconv.FormatFloat(v, 'f', -1, 64)`
- `bool` → `"true"` / `"false"`
- `string` → as-is

**CVSS dan CVSSVersion adalah kind terpisah.** Alasannya: nilainya berada di
field yang berbeda di `Risk`, dan Phase 3 mungkin ingin memperlakukannya
secara berbeda (misal: menampilkan versi skala tanpa harus mem-parsing dari
satu string gabungan).

### 5.2 `Conflict`

Conflict = dua evidence scalar dengan `Kind` sama, tapi `Value` berbeda.

```go
type Conflict struct {
    Kind   EvidenceKind
    Values []ConflictValue
}

type ConflictValue struct {
    Source string
    Value  string
}
```

Conflict **hanya** untuk field scalar yang semantiknya "seharusnya satu nilai":

| Kind | Conflict? | Catatan |
|---|---|---|
| `severity` | ✅ | |
| `cvss` | ✅ | hanya jika `cvss_version` sama |
| `cvss_version` | ✅ | |
| `kev` | ✅ | praktis hanya muncul kalau salah satu bilang true |
| `status` | ✅ | Vulnerability.Status di-emit sebagai
EvidenceKindStatus, tetapi conflict status hanya meaningful jika
vocabulary antar-source sebanding (misal: "Analyzed" vs "Rejected" dari
dua source NVD-family). Jangan menganggap status internal/proses dari
source lain (misal: status enrichment "complete") otomatis conflict
dengan status vulnerability. Phase 2E hanya menandai conflict bila dua
source benar-benar memberikan EvidenceKindStatus yang berbeda
nilainya.|

**CVSS dengan `cvss_version` berbeda bukan conflict.** Contoh: CVSS 3.0 = 7.5
dan CVSS 3.1 = 9.8 dipertahankan sebagai dua evidence terpisah, tanpa
`Conflict`. Ini karena keduanya mengukur hal yang berbeda (skala berbeda),
bukan nilai yang bertentangan untuk pengukuran yang sama.

Bukan conflict:
- `alias`, `reference`, `weakness` — digabung, didedup (dengan aturan provenance)
- `package_range`, `applicability` — defer ke Phase 3
- `mitigation`, `poc`, `patch` — bisa berbeda antar-source, disimpan sebagai multiple evidence

### 5.3 `CorrelatedVulnerability`

```go
type CorrelatedVulnerability struct {
    Identifiers []string      // ID + Aliases, unik, terurut
    Evidence    []Evidence    // semua evidence dari semua source
    Conflicts   []Conflict    // conflict scalar terdeteksi
}
```

Tipis. Tidak ada `SourceRecords`, tidak ada confidence, tidak ada
decision. Field tambahan ditambahkan nanti bila benar-benar diperlukan.

**`Identifiers` berisi semua ID + alias yang berhasil dikorelasikan.**
Phase 2E **tidak** memilih canonical ID. Itu keputusan Phase 3 ke atas.

---

## 6. Aturan Emit Evidence

Evidence **hanya** di-emit ketika nilainya eksplisit dari source.
Zero-value default **tidak** dianggap evidence.

| Field | Emit jika |
|---|---|
| `Vulnerability.ID` | selalu (identitas utama) |
| `Vulnerability.Aliases` | selalu (kalau ada) |
| `Vulnerability.Status` | `!= ""` |
| `Vulnerability.References` | selalu (kalau ada) |
| `Vulnerability.Applicability` | selalu (kalau ada) |
| `Vulnerability.PackageApplicability` | selalu (kalau ada) |
| `Enrichment.VulnerabilityID` | selalu (untuk matching) |
| `Enrichment.Mitigation` | `!= ""` |
| `Enrichment.PoCURL` | `!= ""` |
| `Enrichment.PatchCommitURL` | `!= ""` |
| `Enrichment.Weaknesses` | selalu (kalau ada) |
| `Enrichment.References` | selalu (kalau ada) |
| `Enrichment.Risk.Severity` | `!= ""` |
| `Enrichment.Risk.CVSS` | `!= 0` |
| `Enrichment.Risk.CVSSVersion` | `!= ""` |
| `Enrichment.Risk.KEV` | `== true` (false tidak di-emit) |
| `Enrichment.Risk.EPSS` | `!= 0` |
| `Enrichment.Risk.EPSSPercentile` | `!= 0` |

### 6.1 Aturan khusus `KEV=false`

Phase 2E **tidak** meng-emit evidence untuk `KEV=false`. Alasan: tipe
`Risk.KEV` adalah `bool` biasa, yang tidak dapat membedakan antara
"source eksplisit mengatakan false" dan "source tidak memberikan data KEV".

**Konsekuensi penting yang harus dipahami Phase 3 dan seterusnya:**

```
Tidak adanya evidence KEV  ≠  KEV=false
```

Jika Phase 3 membutuhkan pembedaan eksplisit antara "source bilang false"
dan "source tidak bicara", maka `Risk.KEV` harus diubah menjadi `*bool`
di milestone selanjutnya. Perubahan itu **tidak** dilakukan di Phase 2E
karena akan menyentuh Phase 2D dan memperluas scope.

Aturan ini wajib dites: `KEV=false` tidak menghasilkan evidence KEV, dan
Phase 3 tidak boleh menyimpulkan `KEV=false` hanya dari ketiadaan evidence.

---

## 7. Identity Grouping

Dua record dianggap terkait jika **`{ID} ∪ {Aliases}` mereka beririsan**.

Algoritma: **union-find sederhana**.

1. Kumpulkan semua identifier dari semua `Vulnerability` (dan
   `Enrichment.VulnerabilityID`).
2. Union record yang share identifier.
3. Tiap grup menjadi satu `CorrelatedVulnerability`.

Contoh:

```
NVD:   ID=CVE-2021-41773, Aliases=[]
OSV:   ID=GHSA-xxx, Aliases=[CVE-2021-41773]
```

Keduanya share `CVE-2021-41773` → satu grup.

**Canonical ID:** tidak dipilih di Phase 2E. `Identifiers` berisi semua ID +
alias dalam grup. Phase 3 yang akan memutuskan ID mana yang dipakai untuk
display.

---

## 8. Deduplication dan Provenance

**Aturan dedup:**

1. **Reference:** JANGAN dedup hanya berdasarkan URL. Dua reference dengan
   URL yang sama tetapi dari source berbeda adalah dua evidence berbeda.
   Dedup hanya jika `(URL, Source)` identik — yaitu evidence yang benar-benar
   sama dari source yang sama.

   Sebagai contoh:
   - NVD: URL `https://example/advisory`, source `nvd` → evidence A
   - DBCVE: URL `https://example/advisory`, source `dbcve` → evidence B
   - A dan B **dipertahankan keduanya**, karena provenance berbeda.

   Kalau di masa depan muncul kebutuhan "gabungkan reference dengan URL sama",
   itu keputusan Phase 7 (output), bukan Phase 2E (correlation).

2. **Alias:** digabung menjadi `Identifiers`. Karena identifier bukan
   "evidence dari source", penggabungan tidak menghilangkan provenance
   dari mana alias itu berasal — identifier adalah identitas, bukan klaim.
   Kalau provenance alias dibutuhkan (misal "alias ini diklaim oleh OSV"),
   itu bisa ditambahkan sebagai evidence terpisah di milestone mendatang.

3. **Weakness:** dedup berdasarkan `(ID, Source)` dengan aturan yang sama
   seperti reference. CWE-22 dari NVD dan CWE-22 dari DBCVE adalah dua
   evidence berbeda.

4. **Mitigation / PoC / Patch:** tidak didedup. Dua source yang memberikan
   mitigation berbeda menghasilkan dua evidence `mitigation` berbeda. Ini
   adalah bagian dari nilai correlation: user bisa melihat semua saran.

5. **Scalar (severity, cvss, dll.):** tidak didedup sebagai rule. Kalau ada
   dua nilai identik dari source berbeda, itu tetap dua evidence. Conflict
   detection hanya flag jika nilainya **berbeda**.

**Prinsip:** correlation **tidak boleh** menyembunyikan fakta bahwa dua
source berbeda mengatakan hal yang sama. Setiap evidence punya `Source`
yang jelas.

---

## 9. Field yang TIDAK Masuk `Evidence` (Audit)

Beberapa field sengaja **tidak** di-emit sebagai evidence di Phase 2E.
Audit berikut menjelaskan alasannya.

| Field | Di-emit sebagai evidence? | Alasan |
|---|---|---|
| `Vulnerability.Summary` | ❌ | Teks deskriptif panjang. Bukan fakta scalar. Akan sangat noisy jika diperlakukan sebagai evidence. Output formatter (Phase 7) dapat memilih ringkasan mana yang ditampilkan; Phase 2E tidak perlu memutuskan. |
| `Vulnerability.Details` | ❌ | Sama seperti Summary. |
| `Vulnerability.Published` | ❌ | Timestamp fakta dari source. Bukan bagian dari keputusan applicability. Bisa ditambahkan nanti jika Phase 3 butuh filter "vuln yang dipublikasikan setelah X". |
| `Vulnerability.Modified` | ❌ | Sama seperti Published. |
| `Vulnerability.SourceIdentifier` | ❌ | Identifier administratif dari source (misal email reporter). Bukan informasi applicability. |
| `Enrichment.Summary` | ❌ | Teks deskriptif. Sama seperti Vulnerability.Summary. |
| `Enrichment.Confidence` | ❌ | Ini **confidence dari enricher terhadap data yang dia berikan**, bukan confidence Cevrixa terhadap applicability. Mencampurnya akan membingungkan. Disimpan di `Enrichment` dan bisa diakses Phase 3 kalau perlu. |
| `Enrichment.Attribution` | ❌ | Ini metadata lisensi/atribusi, bukan evidence tentang vulnerability. Bisa ditambahkan nanti sebagai bagian output (Phase 7), bukan correlation. |

**Prinsip audit ini:** field yang tidak masuk evidence adalah field yang:

1. Bersifat naratif (bukan fakta yang bisa dibandingkan antar-source), atau
2. Bersifat administratif (bukan informasi applicability), atau
3. Merupakan metadata yang harus dipertahankan **tetapi tidak boleh**
   dicampur ke dalam decision-relevant evidence.

**Jaminan:** field-field di atas tetap **tersimpan** di dalam
`Vulnerability` / `Enrichment` yang menjadi input `CorrelateAll`. Tidak ada
data yang hilang dari source record. Yang Phase 2E lakukan hanyalah **tidak
mengangkat** mereka menjadi `Evidence`.

Kalau Phase 3 atau Phase 7 membutuhkan salah satu field di atas, mereka
harus mengakses langsung dari `Vulnerability` / `Enrichment` source record
— bukan dari `Evidence`. Ini menjaga `Evidence` tetap fokus dan comparable.

---

## 10. Perubahan Kecil ke Phase 2D

Tambah field ke `domain.Enrichment`:

```go
type Enrichment struct {
    // ... field yang sudah ada ...
    VulnerabilityID string `json:"vulnerability_id,omitempty"`
}
```

Update DBCVE mapper:

```go
out := domain.Enrichment{
    Source:          "dbcve",
    VulnerabilityID: payload.Data.CVEID,   // ← baru
    // ...
}
```

**Backward-compatible** karena `omitempty`.

---

## 11. API

Satu fungsi utama:

```go
// CorrelateAll mengelompokkan vulnerabilities dan enrichments menjadi
// beberapa CorrelatedVulnerability berdasarkan identity overlap
// (ID ∪ Aliases), lalu mengisi evidence & conflict untuk masing-masing.
//
// Tidak ada I/O. Input kosong → output kosong.
func CorrelateAll(
    vulns []domain.Vulnerability,
    enrichments []domain.Enrichment,
) []domain.CorrelatedVulnerability
```

**Kenapa tidak ada error return:** tidak ada I/O, tidak ada input yang bisa
"gagal". Input tidak valid (misal ID kosong) diperlakukan sebagai record
tanpa identifier → dikelompokkan sendiri atau di-skip dengan aman.

**Enrichment matching:** `Enrichment` di-match ke grup melalui
`Enrichment.VulnerabilityID`. Kalau `VulnerabilityID` kosong, enrichment
di-skip dengan aman (tidak di-assign ke grup manapun).

---

## 12. Package Layout

```
internal/domain/
├── evidence.go            BARU
├── correlated.go          BARU
├── enrichment.go          MODIFIKASI (tambah VulnerabilityID)
├── vulnerability.go       tidak diubah
├── target.go              tidak diubah
└── version.go             tidak diubah

internal/correlate/
├── correlate.go           BARU — CorrelateAll()
├── identity.go            BARU — union-find grouping
├── collect.go             BARU — vuln/enrichment → []Evidence
├── conflict.go            BARU — scalar conflict detection
└── *_test.go              BARU

internal/source/dbcve/
└── mapper.go              MODIFIKASI KECIL (isi VulnerabilityID)

PHASE2E.md                 BARU (setelah implementasi selesai)
```

Tidak ada perubahan ke: NVD, OSV, version, cli, cmd, Makefile, ci.yml.

---

## 13. Testing Plan

Test table-driven, fixture sintetik (bukan data CVE real).

Wajib:

1. Satu vulnerability, satu source → satu `CorrelatedVulnerability`,
   evidence minimal.
2. Dua `Vulnerability` dengan `ID` sama → satu grup, evidence dari
   kedua source.
3. Dua `Vulnerability` dengan alias overlap → satu grup.
4. `CVE` + `GHSA` yang share alias → satu grup.
5. Evidence dari multiple source tetap terlihat.
6. Conflict `CVSS` beda value, sama `CVSSVersion` → `Conflict` muncul
   dengan dua `ConflictValue`.
7. Conflict `Severity` beda value → `Conflict` muncul.
8. Reference dengan URL sama dari dua source berbeda → **dua evidence**
   dipertahankan (provenance tidak hilang).
9. Reference dengan URL sama dari source yang sama → didedup jadi satu.
10. Input kosong / ID kosong → tidak panic.
11. `Enrichment` tanpa `VulnerabilityID` → tidak salah di-assign.
12. Non-conflict: reference berbeda, alias berbeda, weakness berbeda →
    tidak menghasilkan `Conflict`.
13. `CVSS` dengan `CVSSVersion` berbeda → **bukan** conflict, dua evidence
    dipertahankan.
14. `KEV=false` tidak di-emit sebagai evidence.
15. `KEV=true` di-emit sebagai evidence dengan `Value="true"`.
16. Test eksplisit: ketiadaan evidence KEV **tidak** disamakan dengan
    `KEV=false` (dokumentasi perilaku).
17. `Vulnerability.Summary`, `Details`, `Published`, `Modified`,
    `SourceIdentifier` **tidak** muncul sebagai evidence.
18. `Enrichment.Summary`, `Confidence`, `Attribution` **tidak** muncul
    sebagai evidence.
19. Weakness sama dari source berbeda → dua evidence (provenance).
20. Mitigation berbeda dari dua source → dua evidence.

Plus: seluruh test NVD/OSV/DBCVE yang sudah ada harus tetap PASS.

---

## 14. Risiko Over-Engineering

Yang **tidak** dilakukan:

- Interface untuk `Evidence`
- Conflict resolution / weighting / confidence
- Semantic range matching
- `Source` sebagai tipe
- Persistence
- CLI integration
- Rule engine untuk conflict (hardcode 5 field scalar)

Batas ukuran:
- `internal/correlate/` (non-test) < ~300 baris
- Satu file < ~150 baris
- Satu fungsi < ~50 baris

---

## 15. Alasan Correlation Dipisahkan dari Detection Engine

- **Correlation** menjawab: "apa yang dikatakan source-source ini tentang
  vulnerability ini?"
- **Detection** menjawab: "apakah target user terpengaruh?"

Dua pertanyaan berbeda. Mencampurnya akan:
- Membuat correlation tidak bisa diuji tanpa target.
- Membuat detection engine bergantung pada detail source.
- Menyulitkan penambahan source baru.

Dengan pemisahan ini, `CorrelateAll` bisa dipakai oleh:
- Detection engine (Phase 3)
- CLI `explain` (Phase 4)
- Output formatter (Phase 7)

tanpa satu pun dari mereka harus tahu schema NVD/OSV/DBCVE.

---

## 16. Acceptance Criteria

Phase 2E dianggap selesai bila:

1. `gofmt -l .` bersih.
2. `go test ./... -count=1` PASS.
3. `go test -race ./... -count=1` PASS.
4. `go build ./...` PASS.
5. `go vet ./...` PASS.
6. `git diff --check` bersih.
7. Semua test di bagian 13 ada dan PASS.
8. Test NVD/OSV/DBCVE yang lama tetap PASS.
9. `PHASE2E.md` selesai dan akurat.
10. Tidak ada perubahan ke `cmd/`, `internal/cli/`, NVD, OSV, version.
11. Tidak ada dependency eksternal baru.

---

## 17. Yang Belum Dilakukan Setelah Phase 2E

Sengaja defer:

- Phase 3: Detection engine (`affected` / `not_affected`)
- Phase 4: Evidence engine, confidence, conflict **resolution**
- Phase 5: SQLite / snapshot
- Phase 6: PURL resolution, ecosystem-aware matching
- Phase 7: JSON/SARIF output, stdin, SBOM

Correlation layer dirancang agar Phase 3 dapat memakainya langsung tanpa
refactor.
