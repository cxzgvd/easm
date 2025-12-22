# 🌐 Advanced EASM - Security R&D Project

> **Eksperymentalny projekt badawczy (R&D) mający na celu demokratyzację systemów klasy External Attack Surface Management poprzez synergię automatyzacji i AI.**

---

## 📑 Geneza i Cel Projektu (The "Why")

Głównym celem tego projektu R&D było sprawdzenie hipotezy: **Czy możliwe jest stworzenie odpowiednika komercyjnych systemów EASM wykorzystując AI.**

Projekt powstał z potrzeby stworzenia "lekkiej", ale wydajnej alternatywy dla ciężkich systemów korporacyjnych. Skupia się na **optymalizacji kosztów (FinOps)** i **maksymalnej automatyzacji** procesów rozpoznania (reconnaissance).

### 🎯 Główne założenia badawcze:
* **AI-Augmented Engineering:** Wykorzystanie modeli LLM do błyskawicznego prototypowania i implementacji zaawansowanych modułów asynchronicznych.
* **Cost-Free Enterprise Security:** Budowa stosu technologicznego opartego wyłącznie na darmowych API i autorskich algorytmach.
* **Scalability:** Zastosowanie modelu `asyncio` do jednoczesnej analizy tysięcy punktów styku z internetem.

---

## 🚀 Architektura Modułowa (R&D Pillars)

Narzędzie realizuje 9 krytycznych wektorów analizy powierzchni ataku:

1.  **Passive Subdomain Discovery (crt.sh):** Pasywne pozyskiwanie listy subdomen z publicznych logów certyfikatów SSL/TLS.
2.  **VirusTotal Intel Integration:** Wykorzystanie danych z VirusTotal do identyfikacji znanych i historycznych subdomen powiązanych z marką.
3.  **Active Async Brute-Force:** Wysokowydajny silnik asynchroniczny, który weryfikuje istnienie tysięcy subdomen w czasie rzeczywistym.
4.  **Cloud Resource Scanner (Multi-Cloud):** Moduł mapujący publiczne zasoby (Buckety S3, Azure Blobs, SQL, CosmosDB) po nazwach organizacji.
5.  **Typosquatting Monitor:** Zaawansowany generator i skaner domen opartych na homoglifach (phishing protection).
6.  **GitHub Leak Detection:** Skanowanie publicznych repozytoriów pod kątem wycieków kluczy API i poufnych danych.
7.  **GitHub Organization Audit:** Mapowanie publicznych struktur organizacji i analiza ryzyka w ich publicznym kodzie.
8.  **Credential Leak Check (HIBP):** Integracja z bazami wycieków w celu identyfikacji skompromitowanych kont w domenie firmowej.
9.  **Async Port Scanner & Banner Grabbing:** Identyfikacja usług na odkrytych IP wraz z pobieraniem banerów i weryfikacją wersji.

---

## 🤖 Rola AI w Projekcie

Projekt jest przykładem **modern software development**. Wykorzystanie AI pozwoliło na:
* **Rapid Prototyping:** Skrócenie czasu przejścia od pomysłu do działającego modułu o ok. 80%.
* **Complex Async Logic:** Implementację czystej i wydajnej logiki asynchronicznej (aiohttp/aiodns), która jest trudna do manualnego debugowania.
* **Threat Prioritization:** (W fazie R&D) Wykorzystanie AI do analizy surowych banerów z portów i oceny realnego ryzyka dla biznesu.

---

## 🛠️ Stack Technologiczny

* **Core:** Python 3.10+ (Asyncio, Aiohttp, Aiodns)
* **API Framework:** Integracja z GitHub, VirusTotal, HIBP
* **Methodology:** R&D, Rapid Prototyping, AI-Assisted Development

---

## 🛡️ Wnioski z badań

Projekt udowodnił, że:
1.  Możliwe jest zbudowanie skutecznej ochrony **Brand Protection** (typosquatting) bez nakładów finansowych na licencje.
2.  Automatyzacja EASM w chmurze Azure jest kluczowa dla firm o dynamicznie rosnącej infrastrukturze (jak sektory publiczne/finansowe).
3.  Połączenie wiedzy analityka SOC z możliwościami AI pozwala na budowę narzędzi szytych na miarę konkretnych potrzeb organizacji w rekordowo krótkim czasie.

