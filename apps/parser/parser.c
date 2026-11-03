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
        memcpy(heap_buffer, input_buffer + offset, length + 8); 
#else
        memcpy(heap_buffer, input_buffer + offset, length);
#endif

#ifdef BUG_P2
        // Nadpisujemy bufor na stosie o 48 bajtów poza deklarowany rozmiar 16B (zapis 64B).
        // Canary wykrywa rozbicie kanarka stosu, MTE wykrywa naruszenie tagu stosu,
        // a ASan/HWASan/Fortify natychmiastowe przekroczenie bufora.
        memcpy(stack_buffer, input_buffer + offset, (size_t)length + 48);
        __asm__ __volatile__("" : "+m"(stack_buffer) :: "memory");
        volatile uint8_t leak_p2 = stack_buffer[0];
        (void)leak_p2;
#else
        stack_buffer[0] = type;
#endif

#ifdef BUG_P3
        memcpy(global_buffer, input_buffer + offset, length + 32);
#endif

#ifdef BUG_P5
        // Atak P5: Sub-granule Overflow (alokacja 8B, nadpisanie 4B wewnątrz tego samego 16B kafelka).
        // Sprzętowe MTE przydziela tagi co 16B, więc bajty 8..11 mają ten sam tag -> MTE ma 0% detekcji!
        // ASan (1B shadow) oraz HWASan (short-granule tag) wykrywają to w 100%!
        uint8_t* sub_buffer = (uint8_t*)malloc(8);
        if (sub_buffer != NULL) {
            memcpy(sub_buffer, input_buffer + offset, 12);
            __asm__ __volatile__("" : "+m"(*(uint8_t(*)[12])sub_buffer) :: "memory");
            volatile uint8_t leak_p5 = sub_buffer[11];
            (void)leak_p5;
            free(sub_buffer);
        }
#endif

#ifdef BUG_P6
        // Atak P6: Data-Oriented Programming (DOP) na stosie.
        // Dwie niezależne zmienne na stosie: `user[16]` oraz flaga `is_admin = 0`.
        // Nadpisujemy bufor `user` poza jego deklarowany rozmiar 16B (zapis 24B).
        // Canary, PAC, BTI, CFI = 0% detekcji! MTE-stack, ASan i HWASan = wykrycie!
        int is_admin = 0;
        char user[16] = {0};
        __asm__ __volatile__("" : "+m"(user), "+m"(is_admin) :: "memory");

        memcpy(user, input_buffer + offset, 24);
        __asm__ __volatile__("" : "+m"(user), "+m"(is_admin) :: "memory");

        volatile uint8_t leak_p6 = (volatile uint8_t)user[20];
        (void)leak_p6;

        if (is_admin != 0) {
            fprintf(stderr, "[!] DOP Sukces: Flaga is_admin nadpisana na %d bez dotykania wskaźników kodu!\n", is_admin);
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
    // mmap-owany region jest chroniony przez kernel (SIGSEGV na granicy strony),
    // co maskowaloby bledy przed sanitizerami.
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