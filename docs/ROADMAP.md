# 🗺️ Roadmap — Full Wiz Technique Replication

Bu roadmap, Wiz Research'ün PHP2Shell tekniğinin tam replikasyonu için kalan adımları belgeliyor.

---

## ✅ Tamamlanan

- [x] Bug 1 — Session upload progress OOM → UAF → RCE
- [x] Bug 2 — Memory disclosure (heap leak)
- [x] Bug 3 — Backtrace use-after-free
- [x] Bug 4 — OPcache SHM confusion
- [x] Chain A — Session LFI ile heap manipulation
- [x] Chain C — Mismatch RCE (type confusion)
- [x] Multi-CMS lab (WordPress, Drupal, Joomla)
- [x] phpMyAdmin lab ortamı
- [x] Detection rules (Suricata, Sigma, Lua)
- [x] Mitigation configs (Apache, Cloudflare, Lighttpd, FrankenPHP)
- [x] Offset profilleri (bookworm-amd64, trixie-amd64, trixie-arm64)

---

## 🔬 Sonraki Adımlar

### Phase 1 — Crash-Free RCE (PG auto_prepend_file)

Wiz'in en ileri tekniği: `PG(auto_prepend_file)` pointer'ını overwrite ederek
crash olmadan RCE elde etmek.

- [ ] `PG()` struct offset tespiti (libphp BSS bölgesinden)
- [ ] `auto_prepend_file` field offset hesaplama
- [ ] Heap spray ile kontrollü string yerleştirme
- [ ] Overwrite → arbitrary file include → code execution
- [ ] Birden fazla PHP sürümü için doğrulama

**Neden önemli:** Mevcut exploit OOM crash sonrası dangling pointer kullanıyor.
PG overwrite tekniği crash olmadan çalışır — çok daha sessiz.

### Phase 2 — zif_ini_set Gadget Araştırması

`zif_ini_set` fonksiyonu runtime'da `ini` değerleri değiştiren internal function.
Gadget olarak kullanılabilirse:

- [ ] `zif_ini_set` offset tespiti (farklı build'ler)
- [ ] Fake `zval` chain ile `ini_set("auto_prepend_file", "/tmp/shell.php")` çağrısı
- [ ] Session temp dosyası ile PHP kodu enjeksiyonu
- [ ] End-to-end chain: upload → ini_set → include → RCE

### Phase 3 — BSS Offset Otomatik Tespiti

Şu anda offset'ler manuel `readelf`/`nm` ile bulunuyor. Otomasyon:

- [ ] `tools/calibrate_offsets.py`'ye BSS section parser ekleme
- [ ] `PG()` global pointer otomatik tespiti
- [ ] `executor_globals` offset tespiti
- [ ] Profil dosyasına BSS offset'leri ekleme
- [ ] CI'da offset doğrulama (Docker build + readelf)

### Phase 4 — Windows Desteği

- [ ] Windows PHP build'leri için offset profilleri
- [ ] XAMPP / WampServer lab ortamları
- [ ] SEH-based exploitation path
- [ ] Windows-specific gadget araştırması

### Phase 5 — Gelişmiş Tespit & Savunma

- [ ] Runtime RASP modülü (PHP extension)
- [ ] eBPF-based kernel monitoring
- [ ] ML-based anomaly detection (session pattern analizi)
- [ ] Honeypot template (decoy PHP server)

---

## 📝 Notlar

- Tüm araştırma yalnızca yetkili test ortamlarında yapılmalıdır
- Yeni chain'ler eklendikçe detection rule'ları da güncellenmelidir
- Her yeni offset profili CI testlerinden geçmelidir
