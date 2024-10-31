// Application layer protocol implementation

#include "application_layer.h"
#include "link_layer.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include "constants.h"
#include <sys/time.h>

// Color definitions using ANSI escape codes
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"

// Function to get packet type as a string based on control field
const char* getPacketType(unsigned char control) {
    switch(control) {
        case START:
            return "START";
        case END:
            return "END";
        case DATA:
            return "DATA";
        default:
            return "UNKNOWN";
    }
}

typedef struct packet {
    int size;
    unsigned char* packet;
} packet;

struct packet nextpacket(FILE *fp, unsigned char p_num) {
    unsigned char* packetdata = (unsigned char*) malloc(PACKET_SIZE * sizeof(unsigned char));
    size_t read = 0;
    packet p;

    packetdata[0] = DATA;
    packetdata[1] = p_num % 255;

    if ((read = fread(packetdata + 4, 1, PACKET_SIZE - 4, fp)) < 0) {
        // printf("Error reading\n");
        printf(RED "[Error] Failed to read from file.%s\n", RESET);
    }
    packetdata[2] = (read & 0xFF00) >> 8;
    packetdata[3] = read & 0x00FF;

    p.size = read + 4;
    p.packet = packetdata;

    // printf("p.size: %d\n", p.size);
    printf(GREEN "[Packet] Created DATA packet, Size: %d bytes, Seq: %d%s\n", p.size, p_num, RESET);

    return p;
}

struct packet setupControlPacket(int fileSize, enum PacketsControlField control) {
    packet p;
    unsigned char* packetData = (unsigned char*) malloc(PACKET_SIZE * sizeof(unsigned char));

    packetData[0] = control;
    packetData[1] = 0x00;
    int num_bytes = 0;
    int copy_size = fileSize;

    while (copy_size != 0) {
        num_bytes += 1;
        copy_size = copy_size >> 8;
    }

    packetData[2] = num_bytes;

    for (int i = 1; i <= num_bytes; i++) {
        packetData[2 + i] = (fileSize >> (8 * (num_bytes - i)) & 0xff);
    }
    p.size = 3 + num_bytes;
    p.packet = packetData;

    // printf("Control Packet [%s] created, Size: %d bytes\n", getPacketType(control), p.size);
    printf(GREEN "[Control] [%s] packet created, Size: %d bytes%s\n", getPacketType(control), p.size, RESET);

    return p;
}

int readControl(enum PacketsControlField control, struct packet p) {
    unsigned char* packet = p.packet;

    if (control == START && packet[0] != START) return -1;
    if (control == END && packet[0] != END) return -1;
    if (control == DATA) return -1;

    if (packet[1] != 0) return -1;

    int k = packet[2];
    int filesize = 0;
    for (int i = 0; i < k; i++) {
        filesize = filesize << 8;
        filesize += packet[3 + i];
    }

    // printf("Parsed Control Packet [%s], File Size: %d bytes\n", getPacketType(control), filesize);
    printf(GREEN "[Control] [%s] packet parsed, File Size: %d bytes%s\n", getPacketType(control), filesize, RESET);

    return filesize;
}

int parseNextPacket(struct packet p, FILE *fp, unsigned char seqNum) {
    unsigned char* packet = p.packet;
    if (packet[0] != DATA) {
        // printf("Not data packet!\n");
        printf(RED "[Error] Received non-DATA packet.%s\n", RESET);
        return -1;
    }
    if (packet[1] != seqNum) {
        // printf("Not right packet sequence number!\n");
        printf(RED "[Error] Sequence number mismatch. Expected: %d, Received: %d%s\n", seqNum, packet[1], RESET);
        return -1;
    }

    // printf("%d, %d \n", packet[2], packet[3]);
    // Commented out as it's a debug statement
    // printf("Received Packet Size: %d bytes\n", (packet[2] * 256) + packet[3]);

    int packetsize = (packet[2] * 256) + packet[3];

    // Correct fwrite usage
    size_t bytesWritten = fwrite(packet + 4, 1, packetsize, fp);
    if (bytesWritten != packetsize) {
        // printf("\nCorrupted: %lu\n", fwrite(packet + 4, packetsize, 1, fp));
        printf(RED "[Error] Failed to write data to file. Expected: %d bytes, Written: %lu bytes%s\n", packetsize, bytesWritten, RESET);
        return -1;
    }

    // printf("\nPacket stored in file: %ld\nData in packet:", (long int) packetsize);
    printf(GREEN "[Packet] Stored %d bytes to file.%s\n", packetsize, RESET);
    /*
    for (int i = 0; i < packetsize; i++) printf("%x ", packet[4 + i]);
    printf("\n");
    */

    return packetsize;
}

void applicationLayer(const char *serialPort, const char *role, int baudRate, int nTries, int timeout, const char *filename) {
    LinkLayerRole linklayerrole;

    if (!strcmp("tx", role)) {
        linklayerrole = LlTx;
        // printf("Role: TRANSMITER\n");
        printf(GREEN "[Role] TRANSMITTER%s\n", RESET);
    } else if (!strcmp("rx", role)) {
        linklayerrole = LlRx;
        // printf("Role: RECEIVER\n");
        printf(GREEN "[Role] RECEIVER%s\n", RESET);
    } else {
        printf(RED "ERROR: Bad role\n%s", RESET);
        return;
    }

    LinkLayer options = {
        .role = linklayerrole,
        .baudRate = baudRate,
        .nRetransmissions = nTries,
        .timeout = timeout
    };
    strcpy(options.serialPort, serialPort);

    int fd = llopen(options);
    if (fd < 0) {
        printf(RED "[Error] llopen failed.%s\n", RESET);
        return;
    }

    unsigned char *datapacket;
    unsigned char p_num = 0;
    int res;

    // printf("role: %d", linklayerrole);
    printf(GREEN "[Info] Link Layer opened with role: %d%s\n", linklayerrole, RESET);

    if (linklayerrole == LlTx) {
        int file_size = 0;
        FILE *file_pointer = NULL;

        file_pointer = fopen("penguin.gif", "rb");
        if (file_pointer == NULL) {
            printf(RED "File could not be opened.\n%s", RESET);
            return;
        }

        fseek(file_pointer, 0, SEEK_END);
        file_size = ftell(file_pointer);
        fseek(file_pointer, 0, SEEK_SET);

        // printf("File size: %d\n", file_size);
        printf(GREEN "[Info] File size: %d bytes%s\n", file_size, RESET);

        struct packet p = setupControlPacket(file_size, START);
        // printf("p.size: %d\n", p.size);
        // for (int i = 0; i < p.size; i++) printf("%x ", p.packet[i]);
        printf(GREEN "[Info] Sending START control packet.%s\n", RESET);
        llwrite(p.packet, p.size);
        free(p.packet); // Free allocated memory

        while (1) {
            p = nextpacket(file_pointer, p_num);
            datapacket = p.packet;
            int datapacketSize = p.size;

            if (datapacketSize > 4) {
                res = llwrite(datapacket, datapacketSize);
            } else {
                break;
            }
            free(datapacket);

            if (res == -1) {
                printf(RED "[Error] llwrite failed.%s\n", RESET);
                return;
            }

            p_num += 1;
        }

        fclose(file_pointer);

        p = setupControlPacket(file_size, END);
        printf(GREEN "[Info] Sending END control packet.%s\n", RESET);
        llwrite(p.packet, p.size);
        free(p.packet); // Free allocated memory

        if (llclose(0) == 1) {
            printf(GREEN "Done.\n%s", RESET);
        } else {
            printf(RED "Error closing connection.\n%s", RESET);
        }

    } else if (linklayerrole == LlRx) {
        int bits_received = 0;

        struct timeval ti, tf;
        double timeTaken;
        gettimeofday(&ti, NULL);

        datapacket = (unsigned char *) malloc(PACKET_SIZE * sizeof(unsigned char));

        res = llread(datapacket, 1);
        bits_received += res * 8;
        struct packet p = {res, datapacket};
        int tamanhofile = readControl(START, p);
        if (tamanhofile == -1) {
            printf(RED "Error reading START control packet.%s\n", RESET);
        }

        char *temp = (char*) malloc(50 * sizeof(char));
        sprintf(temp, filename, "-received%s");
        printf(GREEN "File name: %s%s\n", temp, RESET);

        FILE *file_pointer = NULL;
        file_pointer = fopen(temp, "wb");

        if (file_pointer == NULL) {
            perror("File not found.\n");
            free(temp);
            free(datapacket);
            return;
        }

        free(temp);

        int received = 0;
        while (received < tamanhofile) {
            if ((tamanhofile - received) / PACKET_SIZE == 0) {
                res = llread(datapacket, (tamanhofile - received) % PACKET_SIZE);
            } else {
                res = llread(datapacket, PACKET_SIZE);
            }
            p.size = res;
            p.packet = datapacket;
            res = parseNextPacket(p, file_pointer, p_num);
            received += res;
            bits_received += res * 8;
            p_num += 1;
        }

        if (received != tamanhofile) {
            printf(RED "Something went wrong in receiving\n%s", RESET);
        }

        fclose(file_pointer);

        res = llread(datapacket, 1);
        struct packet p2 = {res, datapacket};
        int file_size = readControl(END, p2);
        if (file_size == -1) {
            printf(RED "Error reading END control packet.%s\n", RESET);
        }
        if (file_size != tamanhofile) {
            printf(RED "Error in file sizes. Expected: %d, Received: %d%s\n", tamanhofile, file_size, RESET);
        }

        gettimeofday(&tf, NULL);

        timeTaken = (tf.tv_sec - ti.tv_sec) * 1e6; // s to us
        timeTaken = (timeTaken + (tf.tv_usec - ti.tv_usec)) / 1e6; // us to s

        printf("\n\t\t\t**** STATISTICS ****\n\n");
        printf("\t\tNumber of bits read = %d\n", bits_received);
        printf("\t\tTime it took to send the file =  %fs\n", timeTaken);

        double R = bits_received / timeTaken;
        double S = R / baudRate;

        printf("\t\tBaudrate = %lf\n", R);
        printf("\t\tS = %lf\n\n", S);

        if (llclose(0) == 1) {
            printf(GREEN "Done.\n%s", RESET);
        } else {
            printf(RED "Error closing connection%s\n", RESET);
        }
    }
    free(datapacket);
}
