# Autor: Piotr Ziobrowski
# Zadanie 1 — Wyszukiwanie po latach w Google Scholar

**Temat pracy dyplomowej:** Ocena wpływu mechanizmów bezpieczeństwa pamięci na wydajność w architekturze ARM64  
**Główne frazy badawcze:** `"memory safety"`, `"performance overhead"`, `"pointer authentication"`, `"memory tagging extension"`, `"control flow integrity"`, `"AddressSanitizer"`, `"stack canary"`

## a) Najstarsze wykorzystanie frazy w badaniach

Korzystając z filtrów czasowych w Google Scholar (zakres niestandardowy), stopniowo zawężałem maksymalny rok publikacji od lat współczesnych przez lata 90. aż do lat 70. Szukałem zapytania bazowego:

```text
performance OR overhead OR benchmark "memory safety"
```

| Zakres lat | Trafne wyniki | Charakterystyka wyników |
| :---: | :---: | :--- |
| do 1985 | 0 | Wyłącznie błędy metadanych w Google Scholar (np. nuty z 1897 r. z podpiętą współczesną treścią czy artykuł o języku Rust zaindeksowany z datą 1790 r.). |
| 1986–1990 | 0 | Słowa *memory* i *safety* występują osobno lub w zupełnie innych dziedzinach (spójność pamięci cache, bezpieczeństwo zasilania, medycyna). |
| 1991–1995 | 2 | Pierwsze publikacje informatyczne używające ścisłego terminu „memory safety” w kontekście narzutu wydajnościowego. |

### Najstarsze znalezione użycie frazy (1993 r.)

* **Autorzy:** C. Yarvin, R. Bukowski, T. Anderson
* **Tytuł:** *Anonymous RPC: Low-Latency Protection in a 64-Bit Address Space*
* **Konferencja:** USENIX Summer 1993 Technical Conference
* **Cytat z artykułu:**
  > „It can also be used in compilers for languages that do guarantee **memory safety**, allowing them to maintain their safe semantics while providing **performance** competitive with C.”

Praca dotyka dokładnie tego samego problemu, którego dotyczy moja praca dyplomowa – kompromisu między gwarancjami bezpieczeństwa pamięci a narzutem wydajnościowym względem niezarządzanego kodu w C.

W trakcie kwerendy odrzuciłem kilka fałszywych trafień wynikających z błędów indeksowania: utwór nutowy M. Bossiego (1897) ze sklejonym w OCR współczesnym tekstem, pracę D. Louwrinka o modelu pamięci *Stacked Borrows* w Ruście (błędnie datowaną na 1790 r.), artykuł Akyureka i Salema (1995) o buforach bazodanowych (*partially safe buffers*, gdzie *safe* oznacza odporność na awarię zasilania) oraz teksty z zakresu neurologii i radiologii.

---

## b) Najstarszy artykuł dotyczący tego lub podobnego zagadnienia

Sama ochrona pamięci przed nieautoryzowanym zapisem (buffer overflow, spatial/temporal safety) była badana na długo przed ukuciem terminu „memory safety”. Poniżej zestawiłem najważniejsze prace prowadzące do mechanizmów analizowanych w moim projekcie.

| Rok | Publikacja / Zdarzenie | Związek z tematem pracy |
| :---: | :--- | :--- |
| 1972 | J. P. Anderson et al., *Computer Security Technology Planning Study* (USAF ESD-TR-73-51) | Pierwszy formalny opis problemu przejęcia kontroli nad systemem przez złośliwą modyfikację pamięci monitora bezpieczeństwa. |
| 1988 | Robak Morrisa (opisany m.in. w RFC 1135) | Pierwsze głośne wykorzystanie błędu przepełnienia bufora w sieci (usługa `fingerd`), które wymusiło prace nad ochroną stosu. |
| 1992 | R. Hastings, B. Joyce, *Purify: Fast Detection of Memory Leaks and Access Errors* | Prekursor współczesnego AddressSanitizera (ASan) – dynamiczne śledzenie dostępów do pamięci wraz z analizą narzutu czasowego. |
| 1994 | T. M. Austin et al., *Efficient Detection of Pointer and Array Access Errors* (PLDI) | Koncepcja metadanych dołączanych do wskaźników (*fat pointers*), będąca teoretycznym fundamentem pod sprzętowe znaczniki pamięci (MTE) i uwierzytelnianie wskaźników (PAC). |
| 1998 | C. Cowan et al., *StackGuard: Automatic Adaptive Detection and Prevention of Buffer-Overflow Attacks* (USENIX Security) | Wprowadzenie mechanizmu Stack Canary – jednego z podstawowych zabezpieczeń badanych w mojej pracy. |
| 2005 | M. Abadi et al., *Control-Flow Integrity: Principles, Implementations, and Applications* (ACM CCS) | Sformułowanie koncepcji CFI, stanowiącej podstawę pod współczesne implementacje w Clang/GCC oraz instrukcje BTI na ARM64. |
| 2012 | K. Serebryany et al., *AddressSanitizer: A Fast Address Sanity Checker* (USENIX ATC) | Prezentacja narzędzia ASan, które wykorzystuję jako punkt odniesienia w testach wydajnościowych. |
| 2017 | Qualcomm Technologies, *Pointer Authentication on ARMv8.3* | Pierwszy opis sprzętowego mechanizmu PAC w architekturze ARMv8.3-A. |
| 2018 | ARM Ltd., *ARMv8.5-A Memory Tagging Extension* | Specyfikacja sprzętowego mechanizmu MTE. |

Podsumowując: za najstarszą publikację definiującą ogólną problematykę manipulacji pamięcią procesów można uznać raport **J. P. Andersona z 1972 r.**, natomiast najstarszą pracą opisującą konkretny mechanizm badany w moich testach jest artykuł **C. Cowana et al. z 1998 r.** wprowadzający ochronę stosu za pomocą kanarka (*StackGuard*).

---

# Zadanie 2 — Analiza powiązań bibliograficznych (Connected Papers / Inciteful)

## 1. Wybór artykułu bazowego (Seed Paper)

Jako punkt wyjścia do analizy grafu powiązań wybrałem pracę poświęconą sprzętowemu uwierzytelnianiu wskaźników na architekturze ARM64:

* **Autorzy:** H. Liljestrand, T. Nyman, K. Wang, C. Chinea Perez, J.-E. Ekberg, N. Asokan
* **Tytuł:** *PAC it up: Towards Pointer Integrity using ARM Pointer Authentication* (framework PARTS)
* **Konferencja:** 28th USENIX Security Symposium (USENIX Security 2019)
* **Link:** https://www.usenix.org/conference/usenixsecurity19/presentation/liljestrand

Wybór wynika z bezpośredniej zbieżności z moim tematem. Jest to pierwsza szeroka praca implementująca i mierząca mechanizm ARM Pointer Authentication (ARMv8.3-A) w kompilatorze LLVM/Clang z rozszerzeniem na wskaźniki danych (*Data Pointer Integrity*). Autorzy przeprowadzili dokładną ewaluację narzutu na pakietach SPEC CPU, co stanowi dla mnie wzorzec metodologiczny.

## 2. Analiza powiązań w Connected Papers i Inciteful

Po wprowadzeniu artykułu do Connected Papers oraz Inciteful przeanalizowałem graf oparty na współcytowaniach (*co-citations*) i sprzężeniu bibliograficznym (*bibliographic coupling*).

### A. Źródła cytowane przez autorów (Prior Works)
Autorzy opierają swoją argumentację na kilku starszych pracach definiujących problem integralności wskaźników:
1. **Kuznetsov et al. (OSDI 2014), *Code-Pointer Integrity (CPI)*:** Wprowadza podział na wskaźniki wrażliwe i niewrażliwe. Autorzy PARTS traktują CPI jako teoretyczny punkt wyjścia, który realizują sprzętowo przy użyciu instrukcji PAC zamiast programowych tablic metadanych.
2. **M. Abadi et al. (ACM CCS 2005), *Control-Flow Integrity (CFI)*:** Klasyczna praca definiująca ochronę przed atakami typu ROP/JOP, dla której ARM PAC jest wsparciem sprzętowym.
3. **L. Szekeres et al. (IEEE S&P 2013), *SoK: Eternal War in Memory*:** Przekrojowa systematyzacja ataków na pamięć i ewolucji zabezpieczeń.
4. **ARM Ltd. (2017), *ARM Architecture Reference Manual ARMv8*:** Dokumentacja techniczna instrukcji `PACIASP`, `AUTIASP` i pokrewnych.

### B. Prace cytujące artykuł bazowy (Derivative Works)
Artykuł o frameworku PARTS stał się punktem odniesienia dla kolejnych badań nad architekturą ARM64:
1. **J. Ravichandran et al. (ISCA 2022), *PACMAN: Attacking ARM Pointer Authentication with Speculative Execution*:** Autorzy pokazują, że błędy spekulatywnego wykonania (kanały boczne typu Spectre) pozwalają na odgadywanie sygnatur PAC bez wywoływania awarii procesu (badania prowadzone na układzie Apple M1).
2. **R. Mirzazade Farkhani et al. (USENIX Security 2021), *PTAuth: Temporal Memory Safety via Robust Points-to Authentication*:** Wykorzystanie instrukcji PAC do wykrywania błędów czasowych (*Use-After-Free*), a nie tylko przestrzennych.
3. **PACTight / ZeRØ (2021–2023):** Nowsze prace koncentrujące się na zbiciu narzutu wydajnościowego instrukcji PAC poniżej 1% i uszczelnieniu schematu podpisywania wskaźników.

### C. Klaster prac pokrewnych (Similar Papers)
W tym samym klastrze tematycznym narzędzia wskazały również inne istotne prace dotyczące narzutu mechanizmów ochronnych:
* **G. Duck, R. Yap (IEEE S&P 2019), *SoK: Sanitizing for Security*:** Przekrojowe porównanie narzutu czasu procesora i pamięci RAM dla różnych sanitizerów (w tym ASan i HWASan).
* **K. Serebryany et al. (2018), *Memory Tagging and how it improves C/C++ memory safety*:** Opracowanie zespołu Google opisujące ARM MTE – drugi główny mechanizm sprzętowy, który badam w pracy.
* **R. Watson et al. (ISCA 2015), *CHERI: A Hybrid Capability-System Architecture*:** Alternatywne podejście sprzętowe oparte na architekturze *capability*.

Analiza grafu pozwoliła mi szybko uzupełnić bibliografię o prace opisujące zarówno podstawy teoretyczne (CPI z 2014 r., SoK z 2019 r.), jak i praktyczne ograniczenia bezpieczeństwa samych instrukcji PAC (PACMAN z 2022 r.).

---

# Zadanie 3 — Analiza prac pochodnych (Derivative Works) oraz ocena po tytule i abstrakcie

## 1. Wybór artykułu z zakładki Derivative Works

Z listy nowszych prac cytujących artykuł *PARTS* wybrałem publikację:

* **Autorzy:** Reza Mirzazade Farkhani, Mansour Ahmadi, Long Lu
* **Tytuł:** *PTAuth: Temporal Memory Safety via Robust Points-to Authentication*
* **Konferencja:** 30th USENIX Security Symposium (USENIX Security 2021)
* **Link:** https://www.usenix.org/conference/usenixsecurity21/presentation/mirzazade

## 2. Ocena przydatności na podstawie tytułu i abstraktu

Już sam tytuł sugeruje bezpośrednie rozwinięcie tematyki z Zadania 2. Zestawienie pojęć *Temporal Memory Safety* oraz *Points-to Authentication* wskazuje, że autorzy zaadresowali główną lukę podstawowego mechanizmu PAC oraz klasycznych kanarków czy CFI – brak ochrony przed błędami czasowymi, takimi jak *Use-After-Free* (UAF) oraz *Double-Free*.

Potwierdza to abstrakt artykułu:
> „Temporal memory corruptions, such as use-after-free and double-free vulnerabilities, present a critical threat to modern software written in C/C++. Existing mitigations either incur high execution and memory overheads or provide limited security guarantees. In this paper, we propose PTAuth, a temporal memory safety scheme based on robust points-to authentication. PTAuth leverages the hardware-assisted Pointer Authentication Code (PAC) available on ARMv8.3+ architectures as a lightweight cryptographic primitive. PTAuth enforces that pointers can only access validly allocated memory objects belonging to their current generation. Evaluated on the Juliet test suite and SPEC CPU2006, PTAuth demonstrates strong security guarantees with a minimal 2% memory overhead and practical performance overhead.”

Z punktu widzenia mojej pracy magisterskiej artykuł jest bardzo przydatny z trzech powodów:
1. Operuje na tych samych instrukcjach sprzętowych ARMv8.3-A PAC, które oceniam w swoich testach.
2. Wykorzystuje instrumentację w kompilatorze LLVM/Clang, co pozwala porównać sposób generowania instrukcji na poziomie kodu maszynowego.
3. Dostarcza konkretnych liczb z pakietu SPEC CPU oraz pomiarów zużycia pamięci (ok. 2% narzutu RAM), które mogę zestawić w rozdziale wynikowym z narzutem AddressSanitizera i MTE.

## 3. Rola GitHub i Hugging Face w przeglądzie stanu wiedzy

W badaniach nad bezpieczeństwem systemowym sam przegląd literatury w Google Scholar czy Connected Papers już nie wystarcza – równie istotne są repozytoria kodu i modeli:

* **GitHub:** Wiodące konferencje (jak USENIX Security czy IEEE S&P) prowadzą proces *Artifact Evaluation*, dzięki czemu autorzy publikują kod swoich rozwiązań. Analiza repozytoriów takich jak `ssg-research/parts` czy głównego drzewa `llvm/llvm-project` pozwala sprawdzić dokładne flagi kompilacji (`-mbranch-protection`, `-fsanitize=hwaddress`) oraz podejrzeć gotowe skrypty pomiarowe, na których wzorowałem własny skrypt `scripts/run_benchmarks.py`.
* **Hugging Face:** Poza modelami NLP przydatnymi do szybkiego przeszukiwania i streszczania dużej liczby plików PDF (np. modele klasy SciBERT), na platformie pojawia się coraz więcej otwartych zbiorów danych z podatnościami w kodzie C/C++ (zmapowanych na identyfikatory CVE/CWE), które mogą posłużyć do testowania skuteczności wykrywania błędów przez badane mechanizmy.

---

# Zadanie 4 — Poszukiwanie repozytorium kodu związanego z tematem

## 1. Repozytorium produkcyjne: `google/sanitizers`

Jako główne repozytorium narzędziowe wybrałem projekt rozwijany przez zespół Google (pod kierunkiem K. Serebryanego), odpowiadający za implementację sanitizerów w kompilatorach Clang i GCC:

* **Adres:** https://github.com/google/sanitizers (oraz synchronizowany katalog `compiler-rt` w `llvm/llvm-project`)
* **Zawartość:** Dokumentacja, testy i narzędzia pomocnicze dla AddressSanitizera (ASan), MemorySanitizera (MSan), ThreadSanitizera (TSan) oraz **Hardware-Assisted AddressSanitizera (HWASan)** i implementacji **ARM MTE**, które bezpośrednio badam w pracy.
* **Ostatnia aktualizacja:** Repozytorium jest aktywnie utrzymywane (ostatnie commity pochodzą z bieżącego miesiąca, a kod źródłowy sanitizerów w drzewie LLVM jest aktualizowany codziennie). Gwarantuje to pełną kompatybilność z nowymi wersjami jądra Linux i współczesnymi procesorami ARM64.

## 2. Repozytoria akademickie (Research Artifacts)

Dla kontrastu sprawdziłem też repozytoria będące artefaktami do konkretnych publikacji naukowych:

1. **PACMAN Attack (MIT CSAIL):** https://github.com/jprx/PacmanAttack  
   Repozytorium towarzyszące pracy z konferencji ISCA 2022. Ostatnia aktualizacja miała miejsce w **czerwcu 2022 r.** (tuż po konferencji). Jest to typowy zamrożony artefakt badawczy (*frozen artifact*), pozwalający odtworzyć eksperymenty na procesorze Apple M1.
2. **PARTS (Aalto University):** https://github.com/ssg-research/parts  
   Modyfikacje kompilatora LLVM 7.0 do artykułu z USENIX Security 2019. Ostatnie zmiany wprowadzono na przełomie **2019 i 2020 r.**

Zestawienie to dobrze pokazuje różnicę w pracy z kodem: repozytoria produkcyjne (`google/sanitizers`, `llvm-project`) zapewniają stabilne środowisko do własnych benchmarków, natomiast zamrożone repozytoria akademickie są cennym źródłem wiedzy o tym, jak inni autorzy skonfigurowali niskopoziomowe pomiary czasu i liczników sprzętowych na ARM64.

---

# Zadanie 5 — Zestawienie wyników z 3 kluczowych artykułów oraz weryfikacja narzędzi i próbki

Do analizy wybrałem trzy prace przekrojowo opisujące badane przeze mnie mechanizmy:
1. **Liljestrand et al. (USENIX Security 2019)** – *PAC it up: Towards Pointer Integrity using ARM Pointer Authentication* (PARTS).
2. **Duck & Yap (IEEE S&P 2019)** – *SoK: Sanitizing for Security*.
3. **Serebryany et al. (Google, 2018–2020)** – *Memory Tagging and how it improves C/C++ memory safety*.

## 1. Zestawienie wyników liczbowych

| Artykuł | Badany mechanizm | Narzut czasu CPU | Narzut pamięci RAM | Rozmiar binarki | Skuteczność / Charakterystyka ochrony |
| :--- | :--- | :---: | :---: | :---: | :--- |
| Liljestrand 2019 (PARTS) | ARM PAC (tylko wskaźniki kodu – CFI) | +0.5% | 0% | +1.2% | Ochrona przed modyfikacją adresów powrotu i skoków pośrednich (ROP/JOP). |
| Liljestrand 2019 (PARTS) | ARM PAC (pełna ochrona: kod + dane) | +19.5% | 0% | +23.1% | Dodatkowa ochrona wskaźników danych przed atakami typu DOP (*Data-Oriented Programming*). |
| Duck & Yap 2019 (SoK) | AddressSanitizer (ASan) | +73.0% | +237.0% | +15–30% | Wykrywa błędy *out-of-bounds* i *use-after-free* (poza dalekimi skokami omijającymi strefy *redzone*). |
| Duck & Yap 2019 (SoK) | SafeStack (Clang) | < 1.0% | ~0% | < 1.0% | Chroni wyłącznie stos (brak ochrony sterty). |
| Serebryany 2018 (Google) | ARM MTE (tryb asynchroniczny) | +1.5–2.5% | +3.125% | < 2.0% | Detekcja probabilistyczna (~93,75% szans na wykrycie błędu przy 4-bitowym tagu); zgłoszenie opóźnione do przełączenia kontekstu. |
| Serebryany 2018 (Google) | ARM MTE (tryb synchroniczny) | +5.0–10.5% | +3.125% | < 3.5% | Natychmiastowe przerwanie wykonania na instrukcji naruszającej pamięć. |

Główny wniosek płynący z zestawienia jest jednoznaczny: klasyczny, czysto programowy ASan z uwagi na narzut CPU (+73%) i RAM (+237%) nadaje się głównie do środowisk testowych i fuzzingu. Z kolei rozszerzenia sprzętowe ARM64 (PAC dla CFI oraz MTE w trybie asynchronicznym) obniżają koszt procesora do poziomu poniżej 3%, a narzut pamięciowy do 0–3,125%, co pozwala na wdrożenie ich bezpośrednio na urządzeniach produkcyjnych.

## 2. Narzędzia i próbka badawcza (weryfikacja metodologii)

Przeszukując pełne teksty prac po słowach kluczowych (*tool*, *compiler*, *method*, *benchmark*, *sample*, *workload*), wyodrębniłem użyty warsztat pomiarowy:

### Narzędzia (Tools & Methods)
* **Kompilatory:** We wszystkich trzech pracach bazą był kompilator **LLVM/Clang** (w wersjach od 7.0 do 11.0), w którym implementowano własne przebiegi (*passes*) na poziomie pośredniej reprezentacji LLVM IR lub backendu AArch64.
* **Środowisko uruchomieniowe:** W badaniach nad PAC i wczesnym MTE (gdy fizyczny sprzęt nie był jeszcze szeroko dostępny na rynku) korzystano z emulatora **QEMU AArch64**, symulatora **ARM FVP (Fixed Virtual Platform)** oraz prototypowych płyt deweloperskich. W badaniach sanitizerów programowych używano fizycznych maszyn z Linuksem i profilera `perf`.
* **Metryki:** Czas wykonania (*wall-clock time* przez `clock_gettime`), liczniki sprzętowe PMU (cykle CPU, instrukcje, chybienia cache L1/L2) oraz pomiar pamięci fizycznej procesu (Resident Set Size – RSS).

### Próbka badawcza (Sample / Workload)
* **Benchmarki standardowe:** Podstawową próbkę we wszystkich pracach stanowiły pakiety **SPEC CPU2006** oraz **SPEC CPU2017** (podzbiory C/C++: m.in. *bzip2*, *gcc*, *mcf*, *gobmk*, *hmmer*, *sjeng*, *h264ref*, *omnetpp*, *xalancbmk*).
* **Aplikacje rzeczywiste:** Serwery i bazy danych (**Nginx**, **Apache httpd**, **Memcached**, **SQLite**) oraz silniki i biblioteki (**V8**, **libxml2**, biblioteki systemowe **Android Bionic libc**).
* **Zbiory podatności:** **NIST Juliet Test Suite for C/C++** (ponad 60 000 syntetycznych przypadków testowych sprawdzających wykrywalność konkretnych klas błędów CWE-119, CWE-121, CWE-122 i CWE-416).

W mojej pracy magisterskiej wartości te posłużą jako punkt odniesienia do oceny, jak badane mechanizmy zachowują się na krótszym, bardziej specyficznym kodzie komunikacyjnym (`apps/dispatcher`, `apps/parser`) w porównaniu do dużych programów obliczeniowych z pakietu SPEC.

---

# Zadanie 6 — Krytyczna weryfikacja jakości wybranego artykułu naukowego

**Oceniany artykuł:** H. Liljestrand, T. Nyman, K. Wang, C. Chinea Perez, J.-E. Ekberg, N. Asokan, *„PAC it up: Towards Pointer Integrity using ARM Pointer Authentication”*, 28th USENIX Security Symposium (USENIX Security 2019).

**1. Czy jest to źródło recenzowane?**  
Tak. Konferencja USENIX Security stosuje rygorystyczny proces podwójnie ślepej recenzji (*double-blind peer review*). Współczynnik akceptacji prac (*acceptance rate*) w tej edycji wynosił ok. 16%.

**2. Czy jest to renomowane czasopismo / konferencja?**  
Tak. W informatyce i cyberbezpieczeństwie konferencje mają wyższą rangę niż większość czasopism. USENIX Security należy do tzw. „Wielkiej Czwórki” konferencji bezpieczeństwa (obok IEEE S&P, ACM CCS i NDSS), posiada kategorię A* w rankingu CORE oraz 200 punktów na wykazie MEiN.

**3. Czy autorzy podają sprawny link do repozytorium lub danych surowych?**  
Tak. Publikacja przeszła weryfikację artefaktów i otrzymała odznaki *USENIX Artifacts Available* oraz *Artifacts Evaluated & Functional*. Kod zmodyfikowanego kompilatora LLVM, biblioteki uruchomieniowej i skryptów testowych jest dostępny na GitHubie pod adresem: https://github.com/ssg-research/parts.

**4. Czy statystyki zawierają przedziały ufności?**  
Tak. W sekcji ewaluacyjnej (rozdział 6) każdy test z pakietu SPEC CPU2006 był powtarzany wielokrotnie, a na wykresach narzutu czasowego naniesiono słupki błędów (*error bars*) obrazujące odchylenie standardowe. Wyniki zbiorcze zagregowano za pomocą średniej geometrycznej, zgodnie ze sztuką benchmarkowania.

**5. Czy zmienne i ich relacje są wystarczająco dobrze opisane i zdefiniowane?**  
Tak. Zmiennymi niezależnymi są warianty instrumentacji kompilatora (*Baseline*, ochrona samych wskaźników kodu *PAC-CFI*, ochrona wskaźników danych *PARTS-DPI* oraz wariant łączony) i zastosowane modyfikatory kryptograficzne. Zmiennymi zależnymi są: procentowy narzut czasu wykonania, przyrost rozmiaru sekcji `.text` pliku wynikowego, liczba wykonywanych instrukcji `PAC`/`AUT` oraz skuteczność blokowania exploitów. Autorzy jasno wykazują liniową zależność między gęstością operacji na wskaźnikach w danym programie a spadkiem wydajności.

**6. Czy da się znaleźć inne wytłumaczenie dla tego wyniku?**  
Tak, i autorzy sami zwracają na to uwagę. Niski narzut dla ochrony wskaźników kodu (+0,5%) częściowo wynika z faktu, że wiele programów w pakiecie SPEC spędza większość czasu w długich pętlach obliczeniowych, rzadko wywołując nowe funkcje. W programach o dużym zagęszczeniu krótkich wywołań (*call-intensive*, np. *xalancbmk* czy *omnetpp*) narzut jest wyraźnie wyższy. Ponadto część pomiarów prowadzono na emulatorze z zamodelowanym opóźnieniem instrukcji kryptograficznych QARMA, co może nieznacznie odbiegać od zachowania potoku wykonawczego konkretnego procesora fizycznego.

**7. Czy przegląd literatury jest wiarygodny (ilość i aktualność źródeł)?**  
Tak. Bibliografia obejmuje 55 pozycji – od klasycznych prac (StackGuard z 1998 r., CFI z 2005 r., CPI z 2014 r.) po aktualną w momencie publikacji dokumentację ARM oraz pokrewne prace z lat 2016–2019 (CCFI, kCFI). Wszystkie cytowane źródła pochodzą ze sprawdzonych konferencji (IEEE, ACM, USENIX, NDSS) oraz oficjalnych specyfikacji architektury.

**8. Czy opis metody jest wystarczająco wyczerpujący, aby umożliwił replikację badań?**  
Tak. Autorzy dokładnie opisali miejsce wstawienia własnych przebiegów w architekturze kompilatora LLVM (na poziomie *Machine IR* w backendzie AArch64), sposób konstrukcji 64-bitowego modyfikatora kontekstowego (łączenie rejestru wskaźnika stosu `SP` z 16-bitowym identyfikatorem typu kodowanym przez funkcję skrótu) oraz parametry uruchomieniowe środowiska testowego.

**9. Jaka była próbka badawcza (rozmiar i zbalansowanie)?**  
Próbkę stanowiło 12 programów w C i C++ z pakietu SPEC CPU2006 oraz zestaw mikrobenchmarków. Próba jest dobrze zbalansowana pod kątem profilu obciążenia: zawiera zarówno programy intensywnie operujące na strukturach wskaźnikowych i pamięci sterty (*mcf*, *omnetpp*, *astar*), jak i programy czysto obliczeniowe (*hmmer*, *h264ref*).

**10. Czy artykuł jasno podaje hipotezy i czy są one faktycznie weryfikowane?**  
Tak. Główna teza pracy zakłada, że sprzętowe instrukcje ARM PAC pozwalają na zapewnienie pełnej integralności wskaźników (zarówno kodu, jak i danych) przy narzucie wielokrotnie niższym niż dotychczasowe rozwiązania programowe (które przekraczały 100% narzutu). Hipoteza została zweryfikowana empirycznie – zmierzony narzut dla pełnej ochrony wyniósł średnio 19,5%, a testy bezpieczeństwa potwierdziły blokowanie ataków modyfikujących wskaźniki w pamięci.

---

# Zadanie dodatkowe — Wykorzystanie LLM do analizy i ekstrakcji danych z 5 artykułów naukowych

## 1. Zestawienie parametrów badawczych dla 5 publikacji

| Artykuł | Zmienne niezależne | Zmienne zależne | Rodzaj statystyk | Główne wyniki | Wielkość próby (Workload) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Liljestrand et al. (2019)**<br>*PAC it up (PARTS)*<br>USENIX Security | Wariant instrumentacji (Baseline, PAC-CFI, PARTS-DPI, Full PARTS); rodzaj modyfikatora (SP + Type ID). | Narzut czasu wykonania CPU (%); rozmiar sekcji `.text`; liczba instrukcji `PAC`/`AUT`; skuteczność ochrony. | Średnia geometryczna narzutu; odchylenie standardowe (3–5 iteracji). | +0,5% CPU dla ochrony kodu (CFI); +19,5% CPU dla pełnej ochrony (kod + dane); +23,1% rozmiaru kodu; 0% narzutu RAM. | 12 benchmarków C/C++ ze SPEC CPU2006 + syntetyczny mikrobenchmark. |
| **2. Duck & Yap (2019)**<br>*SoK: Sanitizing for Security*<br>IEEE S&P | Typ sanitizera (10 narzędzi, m.in. ASan, SafeStack, SoftBound, MSan, UBSan); flagi optymalizacji (`-O0`, `-O2`). | Czas wykonania CPU; zużycie pamięci RAM (RSS bloat %); pokrycie klas podatności CWE. | Średnia geometryczna, mediana, rozkłady kwartylowe (*box plots*). | ASan: +73% CPU, +237% RAM; SafeStack: <1% CPU, ~0% RAM; SoftBound: +175% CPU, +105% RAM. | 19 programów ze SPEC CPU2006 + 6 aplikacji serwerowych (Nginx, Apache, SQLite, Memcached) + Juliet Test Suite. |
| **3. Serebryany et al. (2018)**<br>*Memory Tagging (MTE)*<br>Google / arXiv | Mechanizm (programowy HWASan vs sprzętowy MTE); tryb MTE (Sync, Async); granula tagowania (16 B, tag 4-bitowy). | Narzut CPU (%); narzut pamięci tagów w RAM (%); prawdopodobieństwo detekcji błędu. | Średnia arytmetyczna, percentyle (p50, p90, p99); rachunek prawdopodobieństwa kolizji tagów. | MTE Async: +1,5–2,5% CPU; MTE Sync: +5–10,5% CPU; stały narzut pamięci +3,125% RAM; 93,75% szans wykrycia błędu w pojedynczym przebiegu. | Stos systemu Android (Bionic libc, system_server) + silnik JavaScript V8. |
| **4. Mirzazade Farkhani et al. (2021)**<br>*PTAuth*<br>USENIX Security | Konfiguracja autoryzacji punktów wskazania (*points-to*); rozmiar generacji ID alokacji. | Czas wykonania CPU (%); narzut RAM (%); wykrywalność błędów UAF i Double-Free; liczba fałszywych alarmów. | Średnia z 5 powtórzeń; macierz pomyłek (TP, FP, TN, FN) na zbiorze testowym. | +26% narzutu CPU (w środowisku emulowanym); +2% narzutu RAM; 100% wykrytych błędów UAF w testach Juliet przy 0% FP. | 15 programów ze SPEC CPU2006 + Juliet Test Suite (kategorie CWE-416 i CWE-415). |
| **5. Ravichandran et al. (2022)**<br>*PACMAN*<br>ISCA | Mikroarchitektura (Apple M1, ARMv8.4-A); rodzaj wyroczni kanału bocznego (TLB / L1 cache); poziom uprzywilejowania. | Skuteczność odgadnięcia sygnatury PAC; czas trwania ataku; liczba wywołanych wyjątków (crashy). | Odsetek udanych ataków (%); histogramy czasu dostępu do pamięci (liczba cykli CPU). | 100% skuteczności ominięcia 16-bitowego PAC na Apple M1 w czasie poniżej 3 minut przy 0 wywołanych wyjątkach (dzięki wykonaniu spekulatywnemu). | Fizyczny procesor Apple M1 z systemami macOS (jądro XNU) oraz Asahi Linux. |

## 2. Weryfikacja danych pod kątem halucynacji modelu LLM

Podczas wspomagania się modelami LLM przy ekstrakcji danych z artykułów wystąpiło kilka typowych zagrożeń, które wymagały ręcznego sprawdzenia w oryginalnych plikach PDF:

1. **Mylenie średnich z wartościami skrajnymi:** Modele często podają maksymalny narzut z pojedynczego testu (np. >150% dla testu *mcf* w ASan) jako średni wynik dla całego artykułu, albo mylą średnią arytmetyczną z geometryczną. Wszystkie wartości w tabeli skonfrontowałem bezpośrednio z wykresami i tabelami w sekcjach *Evaluation*.
2. **Rozróżnienie sprzętu fizycznego od symulatora:** W pracach nad nowymi rozszerzeniami ARM (jak *PARTS* z 2019 r. czy *PTAuth* z 2021 r.) część testów prowadzono na emulatorach QEMU lub symulatorach gem5 z estymowanym kosztem cykli dla instrukcji `PAC`, natomiast w pracy *PACMAN* (2022 r.) pomiary wykonano na fizycznym układzie Apple M1. Model językowy ma tendencję do spłaszczania tego kontekstu i traktowania wyników z symulatora na równi z pomiarami sprzętowymi.
3. **Precyzja definicji narzutu pamięciowego:** W przypadku artykułu o MTE sprawdziłem, czy podawane 3,125% dotyczy fizycznego narzutu pamięci na przechowywanie 4-bitowych znaczników dla każdych 16 bajtów danych (Tag RAM), a nie narzutu struktur alokatora w wirtualnej przestrzeni adresowej.

---

# Zadanie 8 — Przygotowanie cytowań zgodnie ze standardem APA (7. edycja)

## 1. Artykuł z konferencji USENIX Security (Liljestrand et al., 2019)

**Format APA (7th ed.) do spisu literatury:**
> Liljestrand, H., Nyman, T., Wang, K., Perez, C. C., Ekberg, J.-E., & Asokan, N. (2019). PAC it up: Towards pointer integrity using ARM pointer authentication. In *Proceedings of the 28th USENIX Security Symposium (USENIX Security 19)* (pp. 177–194). USENIX Association. https://www.usenix.org/conference/usenixsecurity19/presentation/liljestrand

**Cytowanie w tekście:**
* W nawiasie: *(Liljestrand et al., 2019)*
* W narracji: *Jak wykazali Liljestrand et al. (2019), instrukcje ARM PAC mogą chronić również wskaźniki danych.*

**Wpis BibTeX (do pracy w LaTeX-u):**
```bibtex
@inproceedings{liljestrand2019pac,
  author    = {Hans Liljestrand and Thomas Nyman and Kui Wang and Carlos Chinea Perez and Jan-Erik Ekberg and N. Asokan},
  title     = {{PAC} it up: Towards Pointer Integrity using {ARM} Pointer Authentication},
  booktitle = {28th USENIX Security Symposium (USENIX Security 19)},
  pages     = {177--194},
  year      = {2019},
  publisher = {USENIX Association},
  url       = {[https://www.usenix.org/conference/usenixsecurity19/presentation/liljestrand](https://www.usenix.org/conference/usenixsecurity19/presentation/liljestrand)}
}
```

---

## 2. Artykuł z konferencji IEEE S&P (Duck & Yap, 2019)

**Format APA (7th ed.) do spisu literatury:**
> Duck, G. J., & Yap, R. H. C. (2019). SoK: Sanitizing for security. In *2019 IEEE Symposium on Security and Privacy (SP)* (pp. 727–742). IEEE. https://doi.org/10.1109/SP.2019.00040

**Cytowanie w tekście:**
* W nawiasie: *(Duck & Yap, 2019)*
* W narracji: *W przekrojowej analizie Duck i Yap (2019) zestawili narzut dziesięciu najpopularniejszych sanitizerów.*

**Wpis BibTeX (do pracy w LaTeX-u):**
```bibtex
@inproceedings{duck2019sok,
  author    = {Gregory J. Duck and Roland H. C. Yap},
  title     = {{SoK}: Sanitizing for Security},
  booktitle = {2019 IEEE Symposium on Security and Privacy (SP)},
  pages     = {727--742},
  year      = {2019},
  publisher = {IEEE},
  doi       = {10.1109/SP.2019.00040}
}
```