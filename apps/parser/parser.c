#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "utils.h"

uint8_t global_buffer[16] = {0};

__attribute__((noinline)) void parse_records(const uint8_t* input_buffer, size_t size) {
    size_t offset = 0;
    uint8_t stack_buffer[16];
    
    uint64_t start_time = get_time_ns();

    while (offset < size) {
        if (offset + 2 > size) break;
        
        uint8_t type = input_buffer[offset];
        uint8_t length = input_buffer[offset + 1];
        offset += 2;

#ifndef BUG_P4
        if (offset + length > size) break; 
#endif

        uint8_t* heap_buffer = (uint8_t*)malloc(length);
        if (heap_buffer == NULL) {
            fprintf(stderr, "Blad alokacji pamieci!\n");
            break;
        }
        
#ifdef BUG_P1
        // Atak P1: Heap buffer overflow - alokacja `length`, zapis `length + 8`
        memcpy(heap_buffer, input_buffer + offset, length + 8);
        __asm__ __volatile__("" : "+m"(*heap_buffer) :: "memory");
        (void)getpid(); // Punkt synchronizacji dla MTE_ASYNC
        thesis_log_exploit_success("P1_heap_overflow (Przepełnienie bufora sterty wykonane pomyślnie)");
#elif defined(BUG_P4)
        size_t safe_copy = (offset + length <= size) ? length : (size - offset);
        memcpy(heap_buffer, input_buffer + offset, safe_copy);
#else
        memcpy(heap_buffer, input_buffer + offset, length);
#endif

#ifdef BUG_P2
        // Atak P2: Stack buffer overflow (zapis 64B do bufora 16B na stosie)
        // Pojedyncza, czysta operacja wyzwalająca kanarka stosu, MTE-stack, Fortify lub ASan:
        size_t p2_len = (size_t)length + 48;
        memcpy(stack_buffer, input_buffer + offset, p2_len);
        __asm__ __volatile__("" : "+m"(stack_buffer) :: "memory");
        (void)getpid(); // Punkt synchronizacji dla MTE_ASYNC
        thesis_log_exploit_success("P2_stack_overflow (Przepełnienie bufora stosu wykonane pomyślnie)");
#else
        stack_buffer[0] = type;
#endif

#ifdef BUG_P3
        // Atak P3: Global buffer overflow (zapis 48B do bufora sekcji globalnej 16B)
        size_t glob_len = (size_t)length + 32;
        memcpy(global_buffer, input_buffer + offset, glob_len);
        __asm__ __volatile__("" : "+m"(global_buffer) :: "memory");
        (void)getpid(); // Punkt synchronizacji dla MTE_ASYNC
        thesis_log_exploit_success("P3_global_overflow (Przepełnienie bufora globalnego wykonane pomyślnie)");
#endif

#ifdef BUG_P4
        // Atak P4: Out-of-bounds heap read
        if (offset + length > size) {
            volatile uint8_t leak = input_buffer[offset + length];
            (void)leak;
            (void)getpid(); // Punkt synchronizacji dla MTE_ASYNC
            thesis_log_exploit_success("P4_heap_oob_read (Odczyt poza stertą wykonany pomyślnie)");
            free(heap_buffer);
            break;
        }
#endif

#ifdef BUG_P5
        // Atak P5: Sub-granule Overflow (alokacja 8B, zapis 12B wewnątrz tego samego 16B kafelka).
        // Sprzętowe MTE przydziela tagi co 16B, więc bajty 8..11 mają ten sam tag -> MTE ma 0% detekcji!
        // ASan (1B shadow) oraz HWASan (short-granule tag) wykrywają to w 100%!
        size_t alloc_sz = 8;
        size_t copy_sz = 12;
        __asm__ __volatile__("" : "+r"(alloc_sz), "+r"(copy_sz) :: "memory");
        uint8_t* sub_buffer = (uint8_t*)malloc(alloc_sz);
        if (sub_buffer != NULL) {
            memcpy(sub_buffer, input_buffer + offset, copy_sz);
            __asm__ __volatile__("" : "+r"(sub_buffer) :: "memory");
            volatile uint8_t leak_p5 = sub_buffer[11];
            (void)leak_p5;
            free(sub_buffer);
            thesis_log_exploit_success("P5_subgranule_overflow (Zapis wewnątrz 16B kafelka MTE wykonany bez wykrycia)");
        }
#endif

#ifdef BUG_P6
        // Atak P6: Data-Oriented Programming (DOP) na stosie.
        // Używamy struktury o gwarantowanym standardem C układzie pól:
        // user_buffer (16B) bezpośrednio poprzedza is_admin (4B).
        // Nadpisanie nie dotyka wskaźnika ramki ani kanarka stosu!
        struct {
            char user_buffer[16];
            volatile uint32_t is_admin;
        } dop_frame;
        memset(dop_frame.user_buffer, 0, sizeof(dop_frame.user_buffer));
        dop_frame.is_admin = 0;

        uint32_t admin_val = 0x1337BEEF;
        char payload[20];
        memset(payload, 'A', 16);
        memcpy(payload + 16, &admin_val, 4);

        memcpy(dop_frame.user_buffer, payload, 20);
        __asm__ __volatile__("" : "+m"(dop_frame) :: "memory");
        (void)getpid(); // Punkt synchronizacji dla MTE_ASYNC

        if (dop_frame.is_admin == 0x1337BEEF) {
            thesis_log_exploit_success("P6_stack_dop (Flaga is_admin zmodyfikowana na 0x1337BEEF)");
        }
#endif

        static uint64_t packet_counts[256] = {0};
        packet_counts[type]++;

        uint8_t checksum = 0;
        for (int i = 0; i < length; i++) {
            checksum ^= heap_buffer[i]; 
        }
        __asm__ volatile("" : "+r"(checksum));
        
        free(heap_buffer);
        offset += length;
    }
    
    (void)getpid(); // Punkt synchronizacji jądra dla MTE_ASYNC (TFSRE0_EL1)
    uint64_t end_time = get_time_ns();
    printf("Czas_Parsowania_ns:%llu\n", (unsigned long long)(end_time - start_time));
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Uzycie: %s <plik_datasetu.bin>\n", argv[0]);
        return 1;
    }

    const char* filepath = argv[1];
    int fd = open(filepath, O_RDONLY); 
    if (fd == -1) {
        perror("Blad otwarcia pliku");
        return 1;
    }

    struct stat sb; 
    if (fstat(fd, &sb) == -1) { 
        perror("Blad odczytu metadanych pliku");
        close(fd);
        return 1;
    }

    if (sb.st_size == 0) {
        fprintf(stderr, "Plik wejsciowy jest pusty.\n");
        close(fd);
        return 1;
    }

    uint8_t* file_in_memory = (uint8_t*)mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file_in_memory == MAP_FAILED) {
        perror("Blad mapowania pamieci (mmap)");
        close(fd);
        return 1;
    }

    // Kopiujemy dane na heap, zeby sanitizery (ASan/HWASan/MTE) mogly
    // wykryc odczyty poza buforem (P4) i przepelnienia (P1).
    uint8_t* heap_input = (uint8_t*)malloc(sb.st_size);
    if (heap_input == NULL) {
        perror("Blad alokacji pamieci dla kopii danych");
        munmap(file_in_memory, sb.st_size);
        close(fd);
        return 1;
    }
    memcpy(heap_input, file_in_memory, sb.st_size);

    munmap(file_in_memory, sb.st_size);
    close(fd);

    parse_records(heap_input, sb.st_size);

    free(heap_input);
    return 0;
}
