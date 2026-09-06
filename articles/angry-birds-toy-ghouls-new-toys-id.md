# Angry Birds: “Mainan” Baru Toy Ghouls

> **Jenis dokumen:** Analisis intelijen ancaman, malware, deteksi, dan respons insiden  
> **Sumber utama:** Teks riset Kaspersky GERT/Kaspersky Security Services, “Angry Birds: Toy Ghouls’ new toys”, 4 September 2026, yang diberikan langsung oleh pengguna.  
> **Batasan:** Analisis ini tidak melakukan pemeriksaan sampel atau pengayaan IOC eksternal. Rujukan seperti **[Sumber—Communication]** menunjuk ke bagian teks sumber yang disebutkan.

## 1. Executive Summary

Kaspersky melaporkan backdoor kustom pertama yang dikaitkan dengan **Toy Ghouls**, kelompok bermotif finansial yang juga dikenal sebagai **Bearlyfy, Laboo.boo**, dan **Feral Wolf**. Kelompok ini disebut menargetkan organisasi Rusia sejak 2025. Setelah sebelumnya mengandalkan alat dari GitHub, builder ransomware Babuk dan LockBit yang bocor, lalu ransomware kustom GenieLocker, pada awal Juli 2026 aktor mulai memakai dua varian backdoor “Bird”: **mqtt-bird-agent 0.1.0** dan **matrix-bird-agent 0.1.0**. **[Sumber—Introduction]**

Backdoor dikirim ke sistem yang telah dikompromikan melalui **Windows Remote Management (WinRM)** dengan Evil-WinRM atau WinRM-fs, lalu dapat dipasang sebagai layanan Windows. Varian pertama memakai broker MQTT publik HiveMQ, sedangkan varian kedua memakai server Element berbasis Matrix yang dikendalikan penyerang. Keduanya mengirim status dan metrik host, menerima perintah, mengeksekusinya melalui PowerShell atau Windows Command Shell, lalu mengirim hasilnya kembali. **[Sumber—Delivery, Installation, Communication]**

Risiko keseluruhan dinilai **tinggi**: implant memberikan eksekusi perintah jarak jauh dan persistensi sehingga penyerang dapat mempertahankan kendali penuh atas endpoint. Penggunaan layanan/protokol yang mungkin tampak sah juga dapat menyulitkan pemblokiran berbasis domain. Akan tetapi, sumber tidak menjelaskan metode kompromi sebelum penggunaan WinRM, jumlah korban, industri korban, pencurian data, pergerakan lateral, ataupun penyebaran ransomware dalam rangkaian insiden yang sama; hal-hal tersebut tidak boleh dianggap sudah terbukti.

## 2. Key Points

- Dua backdoor kustom yang diamati adalah `mqtt-bird-agent 0.1.0` (HiveMQ) dan `matrix-bird-agent 0.1.0` (Element/Matrix). **[Sumber—Introduction]**
- Aktor menggunakan WinRM, Evil-WinRM, dan WinRM-fs untuk mengirim executable serta `config.toml` ke host yang sebelumnya sudah dikompromikan. Vektor kompromi awal tidak disebutkan. **[Sumber—Delivery]**
- Persistensi menggunakan layanan Windows: `cplsupport` yang menyamar sebagai **Problem Reports Control Panel**, atau `wtas` sebagai **Windows Telemetry Aggregator Service**. **[Sumber—Installation, Indicators of compromise]**
- Konfigurasi sensitif disegel dengan ChaCha20-Poly1305 memakai kunci turunan `MachineGuid`, sehingga blob terikat ke mesin. Varian Element memindahkan konfigurasi ke registry dan menghapus file konfigurasi awal. **[Sumber—Installation]**
- Kedua varian meminta `http://ip-api.com/json` saat startup untuk mengetahui IP publik dan negara host. **[Sumber—Communication]**
- Varian HiveMQ mengambil perintah dan menjalankannya dengan `PowerShell.exe -NonInteractive -NoProfile -Command` dalam mode tersembunyi; varian Matrix menerima pesan berawalan `cmd:` dan memakai command-line Windows. **[Sumber—Communication]**
- Akun Matrix yang ditemukan pada basis data SQLite Element adalah `panel-bot`; tipe pesan kustom mencakup `m.bird.status`, `m.bird.metrics`, dan `m.bird.cmd_response`. **[Sumber—Communication]**
- `broker.hivemq.com` dan `ip-api.com` adalah layanan sah yang disalahgunakan. Pemblokiran global tanpa validasi konteks berisiko menimbulkan dampak operasional.

## 3. Attack Flow

### Rantai serangan yang didukung sumber

**Host sudah dikompromikan (mekanisme tidak dijelaskan)**  
→ **Delivery:** executable dan konfigurasi dikirim melalui WinRM menggunakan Evil-WinRM/WinRM-fs  
→ **Execution:** backdoor dijalankan dalam sesi command line atau dengan opsi instalasi  
→ **Installation dan persistence:** implant mendaftarkan layanan Windows dan memakai argumen internal `--service`/`service`  
→ **Configuration sealing:** field sensitif disegel dengan kunci berbasis `MachineGuid`; varian Matrix menyimpan blob di registry  
→ **Discovery:** request ke `ip-api.com/json` memperoleh IP publik dan negara  
→ **C2:** implant mengirim status/metrik serta mengambil perintah melalui HiveMQ atau ruang Matrix/Element  
→ **Execution:** perintah dijalankan melalui PowerShell (HiveMQ) atau Windows Command Shell (Matrix)  
→ **Response:** stdout, stderr, exit code, dan durasi dikirim ke C2. **[Sumber—Delivery, Installation, Communication]**

### Batas fakta dan inferensi

- **Fakta sumber:** WinRM digunakan untuk delivery ke sistem yang sudah dikompromikan.
- **Belum diketahui:** bagaimana kredensial/hak WinRM diperoleh dan apakah WinRM juga dipakai untuk pergerakan lateral.
- **Inferensi analitis:** instalasi layanan dan penulisan `HKLM` biasanya memerlukan hak administratif. Ini merupakan implikasi teknis yang masuk akal, bukan bukti sumber tentang teknik eskalasi hak akses.
- **Belum terbukti:** deployment GenieLocker, enkripsi data, eksfiltrasi data, pencurian kredensial, atau dampak ransomware pada host yang memuat backdoor ini.

## 4. Malware / Backdoor Analysis

### Persamaan kedua varian

| Area | Perilaku yang dilaporkan |
| --- | --- |
| Mode operasi | Interaktif atau persisten sebagai layanan Windows |
| Konfigurasi | Mencari `config.toml` di working directory, lalu lokasi `%PROGRAMDATA%`; path alternatif dapat diberikan lewat `-c`/`--config` |
| Proteksi konfigurasi | ChaCha20-Poly1305; kunci diturunkan dari `HKLM\Software\Microsoft\Cryptography\MachineGuid`; kegagalan dekripsi menghentikan implant |
| Discovery | `GET http://ip-api.com/json` untuk IP publik dan negara |
| Telemetri | Status online, hostname, timestamp, lokasi, CPU, memori, disk, load average, dan uptime |
| Kemampuan utama | Menerima perintah, menjalankannya, dan mengembalikan stdout, stderr, exit code, serta durasi |

**[Sumber—Installation, Communication]**

### Perbedaan varian

| Fitur | HiveMQ / `mqtt-bird-agent` | Element / `matrix-bird-agent` |
| --- | --- | --- |
| Nama file teramati | `cplsupport.exe` | `wtass.exe` |
| Lokasi konfigurasi fallback | `%PROGRAMDATA%\cplsupport\config.toml` | `%PROGRAMDATA%\SynapseAgent\config.toml` |
| Persistensi | Service `cplsupport` / “Problem Reports Control Panel” | Service `wtas` / “Windows Telemetry Aggregator Service” |
| Penyimpanan konfigurasi | File berisi blob tersegel | File dihapus setelah run pertama; blob disimpan di `HKLM\Software\synapse\Config\SealedConfig` |
| Isi sensitif | `agent_privkey`, `channel_id`, `server_pubkey` | Alamat server, room ID, `access_token`; token sesi dapat ditambahkan setelah login |
| C2 | `broker.hivemq.com:8883` dan cluster penyerang | `meet.element[.]tw`, ruang Matrix, akun `panel-bot` |
| Pengambilan perintah | Request ke jalur `[cluster_id]/cmd/req` | Pesan diawali `cmd:` |
| Interpreter | PowerShell tersembunyi dengan `-NonInteractive -NoProfile -Command` | Windows command-line interface |
| Pengaturan interval | Dari konfigurasi | `config:set_interval`, 5–3600 detik, disimpan di registry |
| Respons | Jalur `[cluster_id]/cmd/res` | Event `m.bird.cmd_response` |

**[Sumber—Installation, Communication, Indicators of compromise]**

> **Catatan protokol:** sumber menggambarkan varian pertama sebagai MQTT/HiveMQ, tetapi juga menuliskan operasi sebagai request GET/POST ke jalur pada port 8883. Tanpa PCAP atau sampel, analisis ini mempertahankan deskripsi sumber dan tidak menyimpulkan framing protokol yang tidak diperlihatkan.

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | Technique ID | Evidence / Reason |
| --- | --- | --- | --- |
| Lateral Movement | Remote Services: Windows Remote Management | T1021.006 | WinRM dengan Evil-WinRM/WinRM-fs digunakan untuk mengirim backdoor dan konfigurasi. Pemetaan perilakunya kuat, tetapi sumber tidak membuktikan bahwa aktivitas ini benar-benar perpindahan antar-host. |
| Persistence; Privilege Escalation | Create or Modify System Process: Windows Service | T1543.003 | Backdoor dapat memasang dirinya sebagai layanan `cplsupport` atau `wtas`. |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Varian HiveMQ mengeksekusi perintah melalui PowerShell dengan parameter yang disebutkan sumber. |
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 | Varian Matrix menjalankan perintah melalui antarmuka command line Windows. |
| Discovery | System Network Configuration Discovery: Internet Connection Discovery | T1016.001 | Request ke `ip-api.com/json` menentukan IP publik dan negara asal host. |
| Discovery | System Information Discovery | T1082 | Implant mengumpulkan hostname serta metrik CPU, memori, disk, load, dan uptime. |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | Varian Matrix berkomunikasi melalui layanan Element/Matrix; sumber juga mendeskripsikan GET/POST pada varian HiveMQ. Pemetaan dibatasi pada komunikasi aplikasi yang dilaporkan. |
| Command and Control | Web Service | T1102 | Penggunaan layanan HiveMQ publik dan messenger Element untuk pertukaran tugas/hasil konsisten dengan penyalahgunaan layanan web sebagai C2. |
| Defense Evasion | Obfuscated/Compressed Files and Information | T1027 | Field konfigurasi sensitif disimpan terenkripsi dengan ChaCha20-Poly1305. Ini menunjukkan penyamaran data konfigurasi, bukan enkripsi payload. |
| Defense Evasion | Modify Registry | T1112 | Varian Matrix menulis sealed configuration dan interval metrik ke registry. |

Pemetaan di atas berasal dari perilaku yang dinyatakan sumber, bukan klaim bahwa Toy Ghouls memiliki profil resmi di MITRE ATT&CK. Taktik dapat bergantung konteks; khususnya penggunaan WinRM tidak membuktikan initial access ataupun lateral movement tanpa timeline autentikasi dan asal koneksi.

## 6. Indicators of Compromise

Semua nilai jaringan dibuat tidak aktif bila memungkinkan. Hash yang tersedia hanya MD5; untuk pencocokan file yang lebih kuat, tim IR perlu memperoleh SHA-256 dari sampel internal.

### File dan hash

| Jenis | Nilai | Catatan |
| --- | --- | --- |
| File / MD5 | `cplsupport.exe` — `BFADBEEE63A4F0BF19EC9DEB8FA58F58` | Varian HiveMQ |
| File / MD5 | `wtass.exe` — `7916C33688385525078BEE504C90F359` | Varian Element |
| Filename | `config.toml` | Generik; gunakan bersama path, service, hash, atau perilaku |

### Registry

- `HKLM\Software\synapse\Config\SealedConfig`
- `HKLM\Software\SynapseAgent\metrics_interval`
- `HKLM\Software\Microsoft\Cryptography\MachineGuid` — **bukan IOC mandiri**; lokasi Windows sah yang dibaca malware untuk derivasi kunci.

### Services

- Service name `cplsupport`; display name `Problem Reports Control Panel`
- Service name `wtas`; display name `Windows Telemetry Aggregator Service`

### Domain, URL, dan endpoint C2

- `meet.element[.]tw`
- `broker.hivemq[.]com:8883` — infrastruktur sah/shared; jangan diblokir hanya berdasarkan domain tanpa menilai penggunaan bisnis
- `hxxp://ip-api[.]com/json` — layanan sah; sinyal kontekstual, bukan bukti kompromi tunggal
- HiveMQ path/topic-like artifacts:
  - `[cluster_id]/status`
  - `[cluster_id]/metrics3`
  - `[cluster_id]/cmd/req`
  - `[cluster_id]/cmd/res`

### Matrix identifiers dan message types

- Pengirim/peran: `panel-bot`
- Prefix perintah: `cmd:`
- Perubahan konfigurasi: `config:set_interval`
- Event/message types: `m.bird.status`, `m.bird.metrics`, `m.bird.cmd_response`

### Verdict produk yang dicantumkan sumber

- `HEUR:Backdoor.Win64.Suptoml.gen`
- `HEUR:Trojan.Script.Zapchast.conf`
- `Backdoor.Win64.Agent.smgdvy`
- `Trojan.Script.Zapchast.abwm`
- `Trojan.Win64.Agent.smgsfo`
- `Trojan.Script.Zapchast.abwo`

### Kategori yang tidak tersedia

Sumber tidak memberikan alamat IP C2, SHA-1/SHA-256, mutex, scheduled task, user-agent, sertifikat TLS/fingerprint, room ID aktual, cluster/channel ID aktual, agent/server public key, path executable hasil instalasi, ataupun daftar organisasi korban. **[Sumber—Indicators of compromise dan keseluruhan teks]**

## 7. Detection Opportunities

### Sinyal yang langsung diturunkan dari sumber

1. **Service creation:** alert jika service name `cplsupport` atau `wtas`, atau display name yang disebutkan, muncul—terutama bila image path mengarah ke binary unsigned/nonstandard.
2. **Hash match:** cari dua MD5 pada inventaris EDR, file events, sandbox, email/web gateway, dan repositori forensik. Setelah sampel ditemukan, hitung SHA-256 dan sebarkan sebagai indikator tambahan.
3. **Registry:** monitor pembuatan/perubahan `SealedConfig` dan `metrics_interval` pada path tepat di atas.
4. **Process behavior:** deteksi proses service baru yang meluncurkan `powershell.exe` dengan kombinasi `-NonInteractive -NoProfile -Command`; korelasikan dengan koneksi keluar.
5. **Network:** cari endpoint non-browser/non-agent yang mengakses `ip-api.com/json`, `meet.element.tw`, atau `broker.hivemq.com` port 8883.
6. **C2 semantics:** bila TLS inspection atau telemetry aplikasi tersedia, cari `m.bird.*`, `config:set_interval`, `cmd:`, serta jalur `cmd/req`, `cmd/res`, `metrics3`, dan `status` dalam konteks koneksi yang sama.

### Rekomendasi korelasi SIEM/EDR tambahan

- Korelasikan dalam satu host dan jendela waktu: **WinRM activity → file creation (`cplsupport.exe`/`wtass.exe` atau `config.toml`) → service installation → koneksi internet**.
- Windows Security Event **4697** dan System log Service Control Manager **7045** berguna untuk service baru; Sysmon Event **1** untuk process creation, **3** untuk network connection, **11** untuk file creation, serta **12–14** untuk registry jika konfigurasi Sysmon mengaktifkannya.
- PowerShell Operational Event **4104** dapat menunjukkan script block/perintah jika logging telah diaktifkan; Security Event **4688** dapat menunjukkan command line jika kebijakan pencatatan command line aktif.
- WinRM Operational logs serta autentikasi Security **4624** perlu diperiksa untuk sumber koneksi, account, logon type, dan waktu yang berdekatan. Jangan menganggap semua WinRM berbahaya; bandingkan dengan jump host dan pola administrasi yang disetujui.
- DNS/proxy/firewall: baseline-kan host dan aplikasi yang sah memakai HiveMQ, Matrix/Element, atau ip-api. Prioritaskan koneksi dari server yang tidak semestinya memakai layanan tersebut, koneksi periodik, dan koneksi oleh binary baru.

### Contoh logika deteksi pseudo-SIEM

```text
service_create
| where service_name in ("cplsupport", "wtas")
   or display_name in ("Problem Reports Control Panel",
                       "Windows Telemetry Aggregator Service")
| join host within 15m (
    network_connection
    | where domain in ("meet.element.tw", "broker.hivemq.com", "ip-api.com")
  )
```

```text
process_create
| where process_name =~ "powershell.exe"
| where command_line has_all ("-NonInteractive", "-NoProfile", "-Command")
| where parent_process is a newly_created_service
```

Logika ini bersifat analitik dan harus diuji terhadap baseline. Parameter PowerShell saja tidak unik; korelasi parent service, file, registry, dan destination meningkatkan presisi.

## 8. Mitigation

### Immediate

1. Isolasi endpoint yang cocok dengan hash, service, atau kombinasi perilaku C2; pertahankan bukti volatile dan disk sebelum eradikasi bila prosedur IR memungkinkan.
2. Hentikan dan nonaktifkan service mencurigakan, tetapi simpan service configuration, binary, `config.toml`, registry hive, Prefetch, Amcache, event log, dan basis data SQLite Element untuk analisis.
3. Cari scope di seluruh estate berdasarkan hash, filename, service, registry, domain, parent-child process, dan sumber koneksi WinRM.
4. Putuskan sesi C2 dan blokir `meet.element[.]tw` bila tidak ada kebutuhan bisnis. Untuk HiveMQ dan ip-api, pilih kontrol berbasis host/process/path atau egress policy sebelum memblokir domain shared secara global.
5. Identifikasi account yang menggunakan WinRM ke host terdampak, nonaktifkan atau reset bila terindikasi kompromi, cabut sesi/token, dan tinjau aktivitas account lain.
6. Ambil sampel secara aman, hitung SHA-256, dan verifikasi seluruh persistence. Reimage endpoint bila integritas tidak dapat dipastikan.

### Short-term

- Batasi WinRM dengan host firewall, management VLAN, jump host, allowlist administrator, dan autentikasi kuat; cegah akses dari workstation biasa.
- Terapkan application control/allowlisting agar executable tidak tepercaya dari lokasi writable tidak dapat menjadi service.
- Aktifkan dan sentralisasi 4688 command line, PowerShell 4104, WinRM Operational, SCM 7045, serta telemetry EDR/Sysmon yang relevan.
- Terapkan egress filtering untuk server: hanya destination dan port yang diperlukan. Alert koneksi MQTT/8883 atau Matrix dari aset tanpa use case.
- Tambahkan IOC host berkeyakinan tinggi ke EDR; perlakukan domain shared sebagai indikator untuk monitoring/korelasi, bukan pemblokiran buta.

### Long-term

- Pisahkan jalur administrasi, gunakan privileged access workstations, akun admin terpisah, just-in-time access, dan MFA pada control plane yang mendukungnya.
- Bangun baseline service, penggunaan WinRM, PowerShell oleh service accounts, dan layanan SaaS/messaging yang diizinkan per kelompok aset.
- Lakukan purple-team exercise untuk rantai WinRM → service → interpreter → encrypted C2 dan ukur apakah telemetry tersedia dari ujung ke ujung.
- Kelola pengecualian layanan bersama secara berbasis identitas proses/perangkat; hindari strategi IOC-domain saja.
- Integrasikan temuan forensik baru—terutama SHA-256, signer, path instalasi, certificate/fingerprint, dan interval beacon—ke detection engineering dan threat-intelligence platform.

## 9. Threat Hunting Recommendations

| Hipotesis | Yang dicari | Sumber log | Perilaku mencurigakan | IOC / ATT&CK |
| --- | --- | --- | --- | --- |
| Toy Ghouls memasang Bird sebagai service | Service name/display name, image path, waktu instalasi | Security 4697, System 7045, EDR service inventory, registry SYSTEM hive | Service baru bernama `cplsupport`/`wtas`, binary unsigned atau path nonstandard | Service IOCs; T1543.003 |
| Delivery dilakukan melalui WinRM | Session WinRM, account, source host, file write | WinRM Operational, 4624/4688, EDR, PowerShell logs | Remote admin dari host/account di luar baseline diikuti `config.toml` atau executable | Evil-WinRM/WinRM-fs context; T1021.006 |
| HiveMQ Bird aktif | Koneksi 8883, DNS, periodicity, process owner | Firewall/NDR, DNS, proxy/TLS metadata, Sysmon 3, EDR | Binary/service baru menghubungi `broker.hivemq.com`, kemudian PowerShell berjalan berulang | Domain + paths; T1102/T1071.001 |
| Matrix Bird aktif | DNS/TLS ke `meet.element.tw`, local Element SQLite artifacts | DNS, proxy, firewall, EDR file access, forensic collection | Non-browser service mengakses domain; database berisi `panel-bot` atau `m.bird.*` | Matrix indicators; T1102/T1071.001 |
| Implant menyegel konfigurasi | Registry writes dan penghapusan `config.toml` | Sysmon 11–14, EDR file/registry, USN Journal, registry hive | Proses yang sama membaca `MachineGuid`, menulis `SealedConfig`, lalu menghapus config | Registry IOC; T1112/T1027 |
| Implant melakukan public-IP discovery | Request ke path tepat dan owning process | Proxy, DNS, NDR, EDR network telemetry | Service/non-browser baru meminta `ip-api.com/json` sesaat sebelum C2 | URL; T1016.001 |
| C2 memicu command execution | Parent-child process dan koneksi sebelum/sesudah eksekusi | EDR process tree, 4688, 4104, Sysmon 1/3 | Service Bird → PowerShell/cmd; output diikuti koneksi C2 | PowerShell flags; T1059.001/T1059.003 |

Setiap hasil hunt harus diklasifikasikan sebagai **confirmed**, **likely**, **benign**, atau **needs enrichment**. Satu koneksi ke layanan sah tidak cukup untuk menyatakan kompromi.

## 10. Analyst Assessment

### Sophistication dan perubahan kapabilitas

Peralihan dari alat publik dan builder ransomware bocor ke GenieLocker serta dua backdoor kustom menunjukkan investasi pengembangan yang meningkat. Desain konfigurasi machine-bound, dua transport C2, persistence service, telemetry terstruktur, perubahan interval, dan pengembalian hasil perintah menunjukkan tooling operasional yang lebih matang daripada penggunaan tool publik semata. Namun, tanpa analisis kode lengkap, riwayat versi, atau bukti operasi berskala besar, tingkat sophistication tidak semestinya dinaikkan menjadi “advanced” hanya dari fitur tersebut.

### Mengapa HiveMQ/MQTT dan Element/Matrix menarik

Secara analitis, keduanya menyediakan infrastruktur dan pola trafik yang dapat bercampur dengan penggunaan sah. MQTT cocok untuk pesan ringan dan koneksi perangkat/agent, sedangkan Matrix menyediakan room, account/token, sinkronisasi pesan, dan pertukaran dua arah. Memanfaatkan layanan semacam ini dapat menekan biaya infrastruktur dan membuat pemblokiran domain lebih berisiko bagi defender. Untuk varian Element, sumber menyatakan servernya dikendalikan penyerang; untuk HiveMQ, domain broker adalah resource sah/shared dan cluster digunakan aktor. **[Sumber—Communication, Takeaways]**

### Tantangan deteksi dan prioritas SOC

- Enkripsi transport dan legitimasi domain dapat membatasi inspeksi konten.
- `config.toml`, PowerShell flags, dan akses ip-api dapat muncul pada aktivitas sah jika dilihat sendiri-sendiri.
- Sealed configuration yang terikat `MachineGuid` menyulitkan analisis konfigurasi di luar host asal; pengumpulan registry dan konteks host menjadi penting.
- Prioritas tertinggi adalah korelasi **remote WinRM + file/service baru + child shell + egress tidak lazim**, bukan pencocokan domain tunggal.
- SOC perlu mencari bukti akses sebelum delivery: account, source host, session WinRM, dan aktivitas administratif lain. Hal ini penting karena sumber memulai rantai pada host yang sudah compromised.

## 11. Source Confidence

### Fakta yang dikonfirmasi oleh sumber riset

Dengan keyakinan **tinggi terhadap isi laporan**, teks Kaspersky GERT/Kaspersky Security Services menyatakan: identitas/alias dan motivasi Toy Ghouls; target organisasi Rusia sejak 2025; dua nama/versi Bird; delivery melalui WinRM; opsi instalasi; mekanisme sealing; service, registry, komunikasi, command execution; serta IOC yang dicantumkan. “Dikonfirmasi” di sini berarti **dinyatakan oleh sumber**, bukan diverifikasi independen dalam analisis ini.

### Inferensi analitis

- Risiko tinggi didasarkan pada kombinasi persistence dan arbitrary command execution.
- Instalasi service serta penulisan HKLM mengindikasikan konteks hak administratif.
- Layanan/protokol yang sah dapat membantu blending dan meningkatkan biaya pemblokiran bagi defender.
- Korelasi multi-sinyal diperkirakan lebih presisi daripada deteksi domain atau command-line tunggal.

### Memerlukan verifikasi tambahan

- Cara host pertama kali dikompromikan dan bagaimana hak/kredensial WinRM diperoleh.
- Jumlah, identitas, dan sektor organisasi korban; timeline lengkap serta cakupan geografis.
- Apakah backdoor dipakai untuk deployment GenieLocker, pergerakan lateral, koleksi, eksfiltrasi, atau ransomware pada insiden yang sama.
- SHA-256, signer, compile metadata, file path instalasi, room/cluster/channel ID, TLS fingerprint, IP resolusi historis, dan interval beacon aktual.
- Detail wire protocol varian HiveMQ, karena deskripsi sumber mencampurkan terminologi broker MQTT dengan operasi GET/POST dan path.
- Independensi atribusi Toy Ghouls dan hubungan alias Bearlyfy/Laboo.boo/Feral Wolf di luar laporan yang diberikan.

## Kesimpulan

Bird memperluas Toy Ghouls dari operasi ransomware menjadi akses persisten yang dapat dikendalikan jarak jauh melalui dua kanal C2 yang tidak biasa. Nilai defensif tertinggi terletak pada artefak host yang spesifik—hash, service, registry—dan korelasi perilaku dari WinRM sampai child shell serta egress. Infrastruktur sah seperti HiveMQ dan ip-api sebaiknya diperlakukan sebagai konteks hunting, bukan otomatis sebagai target blokir universal. Sementara itu, organisasi yang menemukan indikator perlu menganggap endpoint berpotensi berada di bawah kendali penuh penyerang dan melakukan containment, forensic scoping, credential review, serta pemulihan berbasis tingkat kepercayaan terhadap integritas host.
