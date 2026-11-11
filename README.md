# ARM64 — poprawki środowiska badawczego

Wersja przygotowana na podstawie ostatnich załączonych źródeł: `(3)` i README `(2)`.
Zachowano warianty CMake oraz istniejące operacje testowe. Zmieniono obsługę wyników,
inicjalizacji, danych i kosztów. Archiwum nie zawiera nieprzesłanych skryptów VM.

## Uruchomienie w swoim repozytorium

Skopiuj zawartość tego katalogu do katalogu projektu z zachowaniem ścieżek.
Zachowaj swoje skrypty VM. Usuń stare artefakty kompilacji lub użyj nowego katalogu
projektu — nowe markery wymagają ponownego zbudowania binarek.

```bash
python3 -m unittest discover -s tests -v

# Jednorazowa migracja z poprzedniego schematu seedów:
# --force celowo zastępuje komplet wygenerowanych datasetów i manifest.
python3 scripts/generate_datasets.py --force
python3 scripts/generate_datasets.py --verify

# W gościu AArch64 z Clang/Clang++, LLD, CMake i GNU time:
python3 scripts/run_benchmarks.py --profile smoke --shuffle --seed 42
```

Każdy przebieg zapisuje osobny katalog `results/<run_id>/`. Można podać
`--output-dir results/moj_pomiar`, ale katalog musi być nowy lub pusty.
`--environment-note` służy do zapisania wersji QEMU, akceleratora i komendy VM.
Do rysowania potrzebny jest opcjonalny matplotlib; bez niego CSV i JSONL nadal
powstają. Zależności pomiarowe: Python 3.10+, GNU time, readelf, Clang/Clang++,
LLD, CMake oraz narzędzie budowania wybrane przez CMake.

```bash
python3 scripts/run_benchmarks.py --profile thesis --shuffle --seed 42 \
  --environment-note 'Wpisz tutaj rzeczywistą konfigurację środowiska'

python3 scripts/run_benchmarks.py --plots-only --output-dir results/NAZWA_PRZEBIEGU
```

`--plots-only` czyta zapisane CSV. Nie buduje programu, nie pobiera rozmiarów
aktualnych binarek i nie zmienia metadanych pomiaru. Stare CSV z poprzedniego
klasyfikatora nie są automatycznie migrowane — wymagają ponownego pomiaru.

Kody wyjścia runnera: `0` — kompletne wykonanie; `2` — błąd przygotowania;
`3` — zapisano wyniki, ale wystąpiły nieważne próby lub nieudane pomiary.
Kod `3` jest wskazówką walidacyjną, nie wynikiem skuteczności równym zero.

## Znaczenie wyniku pojedynczej próby

| Pole JSONL | Znaczenie |
| --- | --- |
| `valid` | Można ocenić próbę; błędy środowiska i niepotwierdzone awarie są nieważne. |
| `detected` | Konkretny raport potwierdził detekcję naruszenia. |
| `attack_triggered` | Zaobserwowano marker początku operacji lub raport dowodzący jej wykonania. |
| `effect_occurred` | Zaobserwowano istniejący marker `EXPLOIT_SUCCESS`. |
| `prevented` | Potwierdzony detektor zatrzymał wykonanie przed markerem skutku. |
| `invalid_reason` | Powód wyłączenia z mianownika. |

`prevented` nie dowodzi braku jakiejkolwiek częściowej korupcji pamięci.
`effect_occurred` odnosi się do konkretnego miejsca markera: w P2 jest to wykonanie
przepełnienia, a nie potwierdzenie przejęcia sterowania. Detekcja kanarka po tym
markerze daje `detected=true`, `effect_occurred=true`, `prevented=false`.

Pełne dane są w `benchmark_trials_log.jsonl`: stdout, stderr, komenda, wejście,
hashe, PC, run_id i niezależne obserwacje. CSV jest tylko widokiem pomocniczym.
`Liczba_Prob` w tabelach oznacza wyłącznie ważne próby. Zero ważnych prób daje
pustą komórkę CSV / `None` w Pythonie, czyli N/A, a nie 0%.
Starsza nazwa `Zablokowane_Proby` pozostała aliasem `Wykryte_Proby` dla zgodności
formatu; przy interpretacji używaj nowych, jednoznacznych pól.

## Potwierdzanie pułapek CFI, PAC i BTI

Ogólny SIGSEGV/SIGILL nie wystarcza do przypisania mechanizmu. Sam D1 z C-owym
buforem nadal zależy od wygenerowanej ramki, a D4 z `fn+4` wymaga sprawdzenia
pierwszych instrukcji. Operacje tych scenariuszy nie zostały zmienione.
Najpierw potwierdź układ i zamierzony wynik wariantu bazowego na swoim Clangu.

Do zebrania assemblera bez uruchamiania testów:

```bash
python3 scripts/collect_disassembly.py --objdump objdump
```

Jeżeli lokalny objdump nie obsługuje AArch64, wskaż np. `llvm-objdump` albo
`aarch64-linux-gnu-objdump`. Powstaje osobny tekst dla każdej binarki i szablon
`assembly_review/trap_evidence.template.json`. Po przeglądzie skopiuj szablon
na `trap_evidence.json` i uzupełnij wyłącznie potwierdzone miejsca. Przykład
struktury jednego wpisu (wartości SHA i adresu są tutaj przykładowe):

```json
{
  "schema_version": 1,
  "binaries": {
    "disp_D2_cfi": {
      "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
      "sites": [
        {
          "mechanism": "CFI",
          "signal": "SIGILL",
          "pc_offset": "0x1234",
          "review_note": "Uzasadnienie z przeglądu tej konkretnej binarki"
        }
      ]
    }
  }
}
```

```bash
python3 scripts/run_benchmarks.py --profile smoke --efficacy-only \
  --trap-evidence trap_evidence.json
```

Klasyfikator wymaga zgodności SHA256 binarki, sygnału, offsetu PC i markera
początku operacji. Nieznane miejsca zachowuje jako nieważne z pełnym logiem.
Handler podaje `PC_OFFSET` względem początku obrazu ELF, aby ASLR nie wymuszał
wpisywania adresów absolutnych. Przy PAC, gdy dostępny jest tylko uszkodzony
adres docelowy poza obrazem, taka próba pozostaje niepotwierdzona; nie wpisuj
zmyślonego miejsca pułapki. Ten fragment wymaga walidacji docelowego środowiska.

## Dane i model kosztu

- Niezależny seed jest przypisany do kanonicznej nazwy każdego datasetu.
- Zwykłe uruchomienie sprawdza cały manifest przed zapisywaniem danych.
- Brakujący plik jest publikowany dopiero po zgodności z zachowanym hashem.
- `--force` jawnie odtwarza komplet; `--update-manifest` jawnie akceptuje
  istniejący pełny komplet. Żadna z tych opcji nie jest wykonywana przez runner.
- Koszt liczony jest per aplikacja, a dopiero potem uśredniany. Ta sama kolejność
  jest używana w analizie wrażliwości. Zachowano rzeczywiste przyspieszenia.
- Usunięto z warstwy pomiarowej współczynniki tau i obcinanie detekcji do
  arbitralnych pułapów entropii. Ich badanie wymaga osobnego uzasadnionego modelu.
- FTS/PPS są tu jawnymi heurystycznymi indeksami diagnostycznymi. Główną oceną
  pozostają wyniki per scenariusz. Różne zestawy aplikacji i scenariuszy są
  wypisane w tabelach; nie są podstawą automatycznego wspólnego rankingu.
- Nieznane scenariusze nie są zastępowane zerami. Pełny indeks jest N/A, jeśli
  nie ma kompletu ważnych pomiarów. Analiza wrażliwości używa jawnie wyniku na
  faktycznie testowanym zbiorze i ma liniową oraz kwadratową postać indeksu.
- Wilson CI jest wyznaczany per scenariusz dla powtarzanych wykonań. Nie jest
  przedstawiany jako niepewność pokrycia wszystkich możliwych podatności.

Wariant Scudo ma wyłączone pułapki MTE, ale nie zakłada się wyłączenia całego
wewnętrznego tagowania alokatora. Runtime options są zachowane w metadanych.
Domyślna konfiguracja zgodności z poprzednim runnerem wyłącza kwarantannę oraz
kontrole size/type mismatch; można podać własne SCUDO_OPTIONS przed uruchomieniem.

## Zakres sprawdzenia tej paczki

46 testów automatycznych: klasyfikator, logowanie, nieważne próby, glibc,
manifesty, koszty, integracja runnera i dopasowanie zweryfikowanego PC/SHA.
Sprawdzono też generowanie wykresów i składnię C/C++ na x86-64 z flagami
preprocesora projektu. Nie wykonano pełnego builda Clang/AArch64 ani pomiarów
QEMU/chmurowych w tym środowisku. Szczegóły zmian są w `ZMIANY.md`.
