// Link layer protocol implementation

#include "link_layer.h"
#include "constants.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

// Color definitions using ANSI escape codes
#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"

// Function to decide whether to inject an error
int should_inject_error(float error_rate_percentage) {
    float rand_val = ((float)rand()) / RAND_MAX * 100.0; // Random float between 0 and 100
    return (rand_val < error_rate_percentage) ? 1 : 0;
}


// Function to corrupt a frame by flipping a random bit
void corrupt_frame(unsigned char *buf, int size) {
    if (size <= 0) return; // Nothing to corrupt

    int byte_index = rand() % size;            // Select a random byte
    int bit_index = rand() % 8;                // Select a random bit within the byte
    buf[byte_index] ^= (1 << bit_index);       // Flip the selected bit
}


// MISC
#define _POSIX_SOURCE 1 // POSIX compliant source

int alarmEnabled = FALSE;
int alarmCount = 0;

// TODO: Refactor states
enum OpenStates
{
    OPEN_START,
    FLAG_OK,
    ADDR_OK,
    CTRL_OK,
    BCC_OK,
    OPEN_STOP
};

enum CloseStates
{
    CLOSE_START,
    CLOSE_FLAG_OK,
    CLOSE_ADDR_OK,
    DISC_OK,
    CLOSE_CTRL_OK,
    CLOSE_BCC_OK,
    CLOSE_STOP
};

enum Tx_State {
    T_Start,
    T_FLAG_RCV,
    T_ARECEIVED,
    T_CRECEIVED,
    T_BCC_OK,
    T_STOP_STATE
};

enum Rx_State {
    R_Start,
    R_FLAG_RCV,
    R_ARECEIVED,
    R_CRECEIVED,
    R_BCC_OK,
    R_STOP_STATE,
    R_ESCRECEIVED,
    R_ERROR
};

// Alarm function handler
void alarmHandler(int signal)
{
    alarmEnabled = FALSE;
    alarmCount++;

    // printf("Alarm #%d\n", alarmCount);
}

// Frame error
volatile int FRAME_ERROR; // is dependent on something beyond our control

// Connection parameters
LinkLayer connectionParameters;

//////////////////////////////////////////////
// LLOPEN
//////////////////////////////////////////////
#include "serial_port.h"  // Include the serial_port header for API functions

int llopen(LinkLayer link_layer)
{
    // Copy link layer parameters to global connectionParameters
    strcpy(connectionParameters.serialPort, link_layer.serialPort);
    connectionParameters.role = link_layer.role;
    connectionParameters.baudRate = link_layer.baudRate;
    connectionParameters.nRetransmissions = link_layer.nRetransmissions;
    connectionParameters.timeout = link_layer.timeout;

    // Open the serial port using the serial_port API
    if (openSerialPort(connectionParameters.serialPort, connectionParameters.baudRate) < 0)
    {
        perror("openSerialPort failed");
        return -1;
    }

    unsigned char message[5] = { 0 }; // Adjusted to 5 bytes as per frame structure
    unsigned char response[5] = { 0 };
    unsigned char readChar;

    enum OpenStates state = OPEN_START;

    if (connectionParameters.role == LlTx) // TRANSMITTER
    {
        message[0] = FLAG;
        message[1] = A_Tx;
        message[2] = SET;
        message[3] = A_Tx ^ SET; // BCC1
        message[4] = FLAG;

        // Set the alarm function handler
        (void)signal(SIGALRM, alarmHandler);

        while (alarmCount < connectionParameters.nRetransmissions)
        {
            if (alarmEnabled == FALSE)
            {
                // Send SET frame
                if (writeBytesSerialPort(message, 5) < 0) // Send only 5 bytes
                {
                    perror("writeBytesSerialPort failed");
                    closeSerialPort();
                    return -1;
                }

                // Print sent SET frame
                printf(GREEN "[Sent] [%s] Tx -> Rx%s\n", "SET", RESET);

                alarmEnabled = TRUE;
                alarm(connectionParameters.timeout);

                // Wait cycle
                while (state != OPEN_STOP && alarmEnabled == TRUE)
                {
                    // Read a byte using readByteSerialPort instead of read
                    int bytesRead = readByteSerialPort(&readChar);
                    if (bytesRead == -1)
                    {
                        perror("readByteSerialPort failed");
                        closeSerialPort();
                        return -1;
                    }
                    else if (bytesRead == 0)
                    {
                        continue; // No byte read, continue waiting
                    }

                    // Process the byte based on the current state
                    switch (state)
                    {
                    case OPEN_START:
                        if (readChar == FLAG) state = FLAG_OK;
                        break;
                    case FLAG_OK:
                        if (readChar == A_Tx)
                        {
                            state = ADDR_OK;
                            response[1] = readChar;
                        }
                        else if (readChar != FLAG) state = OPEN_START;
                        break;
                    case ADDR_OK:
                        if (readChar == FLAG) state = FLAG_OK;
                        else if (readChar == UA)
                        {
                            state = CTRL_OK;
                            response[2] = readChar;
                        }
                        else state = OPEN_START;
                        break;
                    case CTRL_OK:
                        if (readChar == FLAG) state = FLAG_OK;
                        else if (readChar == (response[1] ^ response[2])) // BCC = A ^ C
                        {
                            response[3] = readChar;
                            state = BCC_OK;
                        }
                        else state = OPEN_START;
                        break;
                    case BCC_OK:
                        if (readChar == FLAG)
                        {
                            response[4] = FLAG;
                            state = OPEN_STOP;
                        }
                        else state = OPEN_START;
                        break;
                    default:
                        break;
                    }

                    // Clear response if back to start
                    if (state == OPEN_START)
                    {
                        memset(response, 0, 5);
                    }
                    else if (state == FLAG_OK)
                    {
                        memset(response, 0, 5);
                        response[0] = FLAG;
                    }
                }
            }

            // Stop if connection established
            if (state == OPEN_STOP)
            {
                printf(GREEN "[Received] [%s] Rx -> Tx%s\n", "UA", RESET);
                break;
            }
        }
    }
    else if (connectionParameters.role == LlRx) // RECEIVER
    {
        while (state != OPEN_STOP)
        {
            int bytesRead = readByteSerialPort(&readChar);
            if (bytesRead == -1)
            {
                perror("readByteSerialPort failed");
                closeSerialPort();
                return -1;
            }
            else if (bytesRead == 0)
            {
                continue; // No byte read, continue waiting
            }

            // Process the byte for RECEIVER role
            switch (state)
            {
            case OPEN_START:
                if (readChar == FLAG) state = FLAG_OK;
                break;
            case FLAG_OK:
                if (readChar == A_Tx)
                {
                    state = ADDR_OK;
                    message[1] = readChar;
                }
                else if (readChar != FLAG) state = OPEN_START;
                break;
            case ADDR_OK:
                if (readChar == FLAG) state = FLAG_OK;
                else if (readChar == SET)
                {
                    state = CTRL_OK;
                    message[2] = readChar;
                }
                else state = OPEN_START;
                break;
            case CTRL_OK:
                if (readChar == (A_Tx ^ SET))
                {
                    message[3] = readChar;
                    state = BCC_OK;
                }
                else if (readChar == FLAG) state = FLAG_OK;
                else state = OPEN_START;
                break;
            case BCC_OK:
                if (readChar == FLAG)
                {
                    message[4] = readChar;
                    state = OPEN_STOP;
                }
                else state = OPEN_START;
                break;
            default:
                break;
            }

            if (state == OPEN_START)
            {
                memset(message, 0, 5);
            }
            else if (state == FLAG_OK)
            {
                memset(message, 0, 5);
                message[0] = FLAG;
            }
        }

        // Print received SET frame
        printf(GREEN "[Received] [%s] Tx -> Rx%s\n", "SET", RESET);

        // Send UA response
        unsigned char ua_response[5] = { FLAG, A_Tx, UA, (A_Tx ^ UA), FLAG };

        if (writeBytesSerialPort(ua_response, 5) < 0) // Send only 5 bytes
        {
            perror("writeBytesSerialPort failed");
            closeSerialPort();
            return -1;
        }

        // Print sent UA frame
        printf(GREEN "[Sent] [%s] Rx -> Tx%s\n", "UA", RESET);
    }

    // Close port on connection failure due to maximum retries
    if (alarmCount >= connectionParameters.nRetransmissions)
    {
        printf(RED "[Error] Connection failed after %d retries.%s\n", connectionParameters.nRetransmissions, RESET);
        closeSerialPort();
        return -1;
    }

    printf(GREEN "CONNECTION ESTABLISHED!\n%s", RESET);
    return 0; // Connection established successfully
}

//////////////////////////////////////////////
// LLWRITE
//////////////////////////////////////////////

int llwrite(const unsigned char *packet, int bufSize)
{
    int frame_to_send = 1;
    unsigned char Data_bcc = 0;
    int fakebufferpos = 0;
    unsigned char buf[IBUF_SIZE] = {0};
    
    while (fakebufferpos < bufSize)
    {
        frame_to_send = !frame_to_send;
        unsigned char RR_ack = RR(!frame_to_send);
        unsigned char REJ_ack = REJ(frame_to_send);

        memset(buf, 0, IBUF_SIZE);
        Data_bcc = 0;

        // Set up frame header
        buf[0] = FLAG;
        buf[1] = A_Tx;
        buf[2] = CONTROL_IFRAME(frame_to_send);
        buf[3] = A_Tx ^ CONTROL_IFRAME(frame_to_send);
        
        int bufpos = 4;
        unsigned char tempbyte;

        // Frame stuffing
        for (int i = 0; i < DATA_BLOCK_SIZE; i++)
        {
            if (fakebufferpos + i >= bufSize) break;
            tempbyte = *(packet + fakebufferpos + i);
            Data_bcc ^= tempbyte;

            if (tempbyte == FLAG || tempbyte == ESC)
            {
                buf[bufpos++] = ESC;
                buf[bufpos++] = tempbyte ^ EXTRA_STUFFS;
            }
            else
            {
                buf[bufpos++] = tempbyte;
            }
        }

        fakebufferpos += DATA_BLOCK_SIZE;

        // Add Data BCC with stuffing if necessary
        if (Data_bcc == FLAG || Data_bcc == ESC)
        {
            buf[bufpos++] = ESC;
            buf[bufpos++] = Data_bcc ^ EXTRA_STUFFS;
        }
        else
        {
            buf[bufpos++] = Data_bcc;
        }

        buf[bufpos++] = FLAG; // Frame end

        alarmCount = 0;
        alarmEnabled = FALSE;
        (void)signal(SIGALRM, alarmHandler);

        // Transmission and acknowledgment wait loop
        while (alarmCount < connectionParameters.nRetransmissions)
        {
            if (alarmEnabled == FALSE)
            {

                int bytes_written;

                // **Error Injection Before Sending DATA Frame**
                if (should_inject_error(PROBABILITY_ERROR)) {
                    // Preserve the original frame
                    unsigned char buf_copy[IBUF_SIZE];
                    memcpy(buf_copy, buf, bufpos);
                    
                    corrupt_frame(buf_copy, bufpos); // Corrupt the DATA frame
                    printf(YELLOW "Artificial error injected into DATA frame.%s\n", RESET);
                    
                    // Send frame using writeBytesSerialPort
                    writeBytesSerialPort(buf_copy, bufpos);
                    if (bytes_written < 0)
                    {
                        perror("writeBytesSerialPort failed");
                        return -1;
                    }
                }else{
                    // Send frame using writeBytesSerialPort
                    writeBytesSerialPort(buf, bufpos);
                    if (bytes_written < 0)
                    {
                        perror("writeBytesSerialPort failed");
                        return -1;
                    }
                }

                // Print sent I-frame
                printf(GREEN "[Sent] [DATA] Tx -> Rx, Seq: %d%s\n", frame_to_send, RESET);

                alarm(connectionParameters.timeout);
                alarmEnabled = TRUE;
                sleep(1); // Wait for transmission

                // Wait for acknowledgment
                unsigned char readChar;
                FRAME_ERROR = FALSE;
                enum Tx_State state = T_Start;
                unsigned char commandbuff[TRANSMITTER_READ_BUFF_SIZE] = {0};

                while (alarmEnabled == TRUE && state != T_STOP_STATE)
                {
                    int bytesRead = readByteSerialPort(&readChar);
                    if (bytesRead == -1)
                    {
                        perror("readByteSerialPort failed");
                        return -1;
                    }
                    else if (bytesRead == 0)
                    {
                        continue; // No byte read, continue waiting
                    }

                    // Process acknowledgment byte by byte
                    switch (state)
                    {
                    case T_Start:
                        if (readChar == FLAG)
                            state = T_FLAG_RCV;
                        break;
                    case T_FLAG_RCV:
                        if (readChar == A_Tx)
                        {
                            state = T_ARECEIVED;
                            commandbuff[1] = readChar;
                        }
                        else if (readChar != FLAG)
                        {
                            state = T_Start;
                        }
                        break;
                    case T_ARECEIVED:
                        if (readChar == FLAG)
                        {
                            state = T_FLAG_RCV;
                        }
                        else if (readChar == REJ_ack || readChar == RR_ack)
                        {
                            state = T_CRECEIVED;
                            commandbuff[2] = readChar;
                        }
                        else
                        {
                            state = T_Start;
                        }
                        break;
                    case T_CRECEIVED:
                        if (readChar == (commandbuff[1] ^ commandbuff[2]))
                        {
                            commandbuff[3] = readChar;
                            state = T_BCC_OK;
                        }
                        else if (readChar == FLAG)
                        {
                            state = T_FLAG_RCV;
                        }
                        else
                        {
                            state = T_Start;
                        }
                        break;
                    case T_BCC_OK:
                        if (readChar == FLAG)
                        {
                            commandbuff[4] = FLAG;
                            state = T_STOP_STATE;
                        }
                        else
                        {
                            state = T_Start;
                        }
                        break;
                    default:
                        break;
                    }

                    // Reset if back to start
                    if (state == T_Start)
                    {
                        memset(commandbuff, 0, TRANSMITTER_READ_BUFF_SIZE);
                    }
                    else if (state == T_FLAG_RCV)
                    {
                        memset(commandbuff, 0, TRANSMITTER_READ_BUFF_SIZE);
                        commandbuff[0] = FLAG;
                    }
                    else if (state == T_STOP_STATE && commandbuff[2] == REJ_ack)
                    {
                        FRAME_ERROR = TRUE;
                    }
                }

                // Handle acknowledgment
                if (state == T_STOP_STATE)
                {
                    if (commandbuff[2] == RR_ack)
                    {
                        printf(GREEN "[Received] [RR] Rx -> Tx, Seq: %d%s\n", frame_to_send, RESET);
                        break; // Frame acknowledged successfully
                    }
                    else if (commandbuff[2] == REJ_ack)
                    {
                        printf(RED "[Received] [REJ] Rx -> Tx, Seq: %d%s\n", frame_to_send, RESET);
                        FRAME_ERROR = TRUE;
                    }
                }

                // Retransmit if frame error occurred
                if (FRAME_ERROR == TRUE)
                {
                    printf(RED "[Error] Frame %d corrupted. Retransmitting...%s\n", frame_to_send, RESET);
                    alarmCount = 0;
                    continue;
                }
            }

            // Exceeded retransmission limit, close port
            if (alarmCount >= connectionParameters.nRetransmissions)
            {
                printf(RED "[Error] Exceeded maximum retransmissions for frame %d%s\n", frame_to_send, RESET);
                closeSerialPort();
                return -1;
            }
        }
    }
    return 1; // Full data successfully sent
}

//////////////////////////////////////////////
// LLREAD
//////////////////////////////////////////////

int llread(unsigned char *packet, int packet_size)
{
    int frame_number = 0;
    int packetposition = 0;
    unsigned char messagebuffer[5] = {0};
    unsigned char frame[DATA_BLOCK_SIZE] = {0};
    unsigned char controlbuffer[6] = {0};
    
    while (packetposition < packet_size)
    {
        memset(frame, 0, DATA_BLOCK_SIZE);
        memset(controlbuffer, 0, 6);
        int framepos = 0;
        unsigned char data_bcc = 0x0;
        unsigned char frame_required = CONTROL_IFRAME(frame_number);
        unsigned char prev_frame = CONTROL_IFRAME(!frame_number);

        enum Rx_State state = R_Start;
        unsigned char readChar;

        while (state != R_STOP_STATE && state != R_ERROR)
        {
            int bytesRead = readByteSerialPort(&readChar);
            if (bytesRead == -1)
            {
                perror("readByteSerialPort failed");
                return -1;
            }
            else if (bytesRead == 0)
            {
                continue; // No byte read, continue waiting
            }

            // Process the byte according to the current state
            switch (state)
            {
            case R_Start:
                if (readChar == FLAG)
                    state = R_FLAG_RCV;
                break;
            case R_FLAG_RCV:
                if (readChar == A_Tx)
                {
                    state = R_ARECEIVED;
                    controlbuffer[1] = readChar;
                }
                else if (readChar != FLAG)
                {
                    state = R_Start;
                }
                break;
            case R_ARECEIVED:
                if (readChar == FLAG)
                {
                    state = R_FLAG_RCV;
                }
                else if (readChar == frame_required || readChar == prev_frame)
                {
                    state = R_CRECEIVED;
                    controlbuffer[2] = readChar;
                }
                else
                {
                    state = R_Start;
                }
                break;
            case R_CRECEIVED:
                if (readChar == (controlbuffer[1] ^ controlbuffer[2]))
                {
                    state = R_BCC_OK;
                }
                else if (readChar == FLAG)
                {
                    state = R_FLAG_RCV;
                }
                else
                {
                    state = R_Start;
                }
                break;
            case R_BCC_OK:
                if (readChar == FLAG)
                {
                    state = R_STOP_STATE;
                }
                else if (readChar == ESC)
                {
                    state = R_ESCRECEIVED;
                }
                else
                {
                    frame[framepos++] = readChar;
                    data_bcc ^= readChar;
                }
                break;
            case R_ESCRECEIVED:
                state = R_BCC_OK;
                if ((readChar ^ EXTRA_STUFFS) == FLAG || (readChar ^ EXTRA_STUFFS) == ESC)
                {
                    frame[framepos++] = readChar ^ EXTRA_STUFFS;
                    data_bcc ^= readChar ^ EXTRA_STUFFS;
                }
                else
                {
                    state = R_ERROR;
                }
                break;
            default:
                break;
            }

            // Reset control and frame if starting over
            if (state == R_Start)
            {
                memset(frame, 0, DATA_BLOCK_SIZE);
                memset(controlbuffer, 0, 6);
                framepos = 0;
                data_bcc = 0x0;
            }
            else if (state == R_FLAG_RCV)
            {
                memset(controlbuffer, 0, 6);
                memset(frame, 0, DATA_BLOCK_SIZE);
                controlbuffer[0] = FLAG;
                data_bcc = 0x0;
                framepos = 0;
            }
            else if (state == R_STOP_STATE)
            {
                framepos--; // Exclude the Data BCC byte from the data frame
                if (data_bcc != 0x00)
                {
                    state = R_ERROR;
                }
            }
        }

        // Prepare response based on frame status
        messagebuffer[0] = FLAG;
        messagebuffer[1] = A_Tx;
        messagebuffer[4] = FLAG;

        if (state == R_ERROR)
        {
            messagebuffer[2] = (controlbuffer[2] == frame_required) ? REJ(frame_number) : RR(frame_number);
            printf(RED "[Received] [Corrupted I] Rx -> Tx, Seq: %d%s\n", frame_number, RESET);
            printf(RED "[Sent] [%s] Tx -> Rx, Seq: %d%s\n", "REJ", frame_number, RESET);
        }
        else
        {
            if (controlbuffer[2] == frame_required)
            {
                memcpy(packet + packetposition, frame, framepos);
                packetposition += framepos;
                frame_number = !frame_number;
                printf(GREEN "[Received] [DATA] Rx -> Tx, Seq: %d%s\n", frame_number, RESET);
            }
            messagebuffer[2] = RR(frame_number);
            printf(GREEN "[Sent] [RR] Tx -> Rx, Seq: %d%s\n", frame_number, RESET);
        }

        messagebuffer[3] = messagebuffer[1] ^ messagebuffer[2];

        // Send acknowledgment (RR or REJ) using writeBytesSerialPort
        if (writeBytesSerialPort(messagebuffer, 5) < 0)
        {
            perror("writeBytesSerialPort failed");
            return -1;
        }
        sleep(1); // Wait for acknowledgment to send
    }

    return packetposition; // Number of bytes received and stored in packet
}


//////////////////////////////////////////////
// LLCLOSE
//////////////////////////////////////////////

int llclose(int showStatistics)
{
    unsigned char message[5] = { FLAG, A_Tx, DISC, (A_Tx ^ DISC), FLAG };
    unsigned char readChar;
    
    if (connectionParameters.role == LlTx) // TRANSMITTER
    {
        // Set up the alarm function handler
        alarmCount = 0;
        alarmEnabled = FALSE;
        (void)signal(SIGALRM, alarmHandler);

        // Transmission and acknowledgment wait loop for DISC
        while (alarmCount < connectionParameters.nRetransmissions)
        {
            if (alarmEnabled == FALSE)
            {
                // Send DISC using writeBytesSerialPort
                if (writeBytesSerialPort(message, 5) < 0) // Send only 5 bytes
                {
                    perror("writeBytesSerialPort failed");
                    closeSerialPort();
                    return -1;
                }

                // Print sent DISC frame
                printf(GREEN "[Sent] [%s] Tx -> Rx%s\n", "DISC", RESET);

                alarmEnabled = TRUE;
                alarm(connectionParameters.timeout);
                sleep(1); // Wait for transmission

                // Wait for DISC acknowledgment
                enum CloseStates state = CLOSE_START;
                unsigned char rx_response[5] = {0};

                while (alarmEnabled == TRUE && state != CLOSE_STOP)
                {
                    int bytesRead = readByteSerialPort(&readChar);
                    if (bytesRead == -1)
                    {
                        perror("readByteSerialPort failed");
                        closeSerialPort();
                        return -1;
                    }
                    else if (bytesRead == 0)
                    {
                        continue; // No byte read, continue waiting
                    }

                    // Process received DISC acknowledgment byte by byte
                    switch (state)
                    {
                    case CLOSE_START:
                        if (readChar == FLAG)
                            state = CLOSE_FLAG_OK;
                        break;
                    case CLOSE_FLAG_OK:
                        if (readChar == A_Tx)
                        {
                            state = CLOSE_ADDR_OK;
                            rx_response[1] = readChar;
                        }
                        else if (readChar != FLAG)
                        {
                            state = CLOSE_START;
                        }
                        break;
                    case CLOSE_ADDR_OK:
                        if (readChar == FLAG)
                        {
                            state = CLOSE_FLAG_OK;
                        }
                        else if (readChar == DISC)
                        {
                            state = DISC_OK;
                            rx_response[2] = readChar;
                        }
                        else
                        {
                            state = CLOSE_START;
                        }
                        break;
                    case DISC_OK:
                        if (readChar == (rx_response[1] ^ rx_response[2]))
                        {
                            rx_response[3] = readChar;
                            state = CLOSE_BCC_OK;
                        }
                        else if (readChar == FLAG)
                        {
                            state = CLOSE_FLAG_OK;
                        }
                        else
                        {
                            state = CLOSE_START;
                        }
                        break;
                    case CLOSE_BCC_OK:
                        if (readChar == FLAG)
                        {
                            rx_response[4] = readChar;
                            state = CLOSE_STOP;
                        }
                        else
                        {
                            state = CLOSE_START;
                        }
                        break;
                    default:
                        break;
                    }
                }

                if (state == CLOSE_STOP)
                {
                    // Print received DISC acknowledgment
                    printf(GREEN "[Received] [%s] Rx -> Tx%s\n", "DISC", RESET);

                    // Prepare and send UA response after receiving DISC
                    unsigned char ua_message[5] = { FLAG, A_Tx, UA, (A_Tx ^ UA), FLAG };
                    if (writeBytesSerialPort(ua_message, 5) < 0) // Send only 5 bytes
                    {
                        perror("writeBytesSerialPort failed");
                        closeSerialPort();
                        return -1;
                    }

                    // Print sent UA frame
                    printf(GREEN "[Sent] [%s] Tx -> Rx%s\n", "UA", RESET);
                    break;
                }
            }
        }
    }
    else if (connectionParameters.role == LlRx) // RECEIVER
    {
        enum CloseStates state = CLOSE_START;
        
        // Wait for DISC from transmitter
        while (state != CLOSE_STOP)
        {
            int bytesRead = readByteSerialPort(&readChar);
            if (bytesRead == -1)
            {
                perror("readByteSerialPort failed");
                closeSerialPort();
                return -1;
            }
            else if (bytesRead == 0)
            {
                continue; // No byte read, continue waiting
            }

            // Process DISC frame
            switch (state)
            {
            case CLOSE_START:
                if (readChar == FLAG)
                    state = CLOSE_FLAG_OK;
                break;
            case CLOSE_FLAG_OK:
                if (readChar == A_Tx)
                {
                    state = CLOSE_ADDR_OK;
                    message[1] = readChar;
                }
                else if (readChar != FLAG)
                {
                    state = CLOSE_START;
                }
                break;
            case CLOSE_ADDR_OK:
                if (readChar == FLAG)
                {
                    state = CLOSE_FLAG_OK;
                }
                else if (readChar == DISC)
                {
                    state = DISC_OK;
                    message[2] = readChar;
                }
                else
                {
                    state = CLOSE_START;
                }
                break;
            case DISC_OK:
                if (readChar == (message[1] ^ message[2]))
                {
                    state = CLOSE_BCC_OK;
                    message[3] = readChar;
                }
                else if (readChar == FLAG)
                {
                    state = CLOSE_FLAG_OK;
                }
                else
                {
                    state = CLOSE_START;
                }
                break;
            case CLOSE_BCC_OK:
                if (readChar == FLAG)
                {
                    message[4] = readChar;
                    state = CLOSE_STOP;
                }
                else
                {
                    state = CLOSE_START;
                }
                break;
            default:
                break;
            }
        }

        // Print received DISC frame
        printf(GREEN "[Received] [%s] Tx -> Rx%s\n", "DISC", RESET);

        // Send DISC in response
        if (writeBytesSerialPort(message, 5) < 0) // Send only 5 bytes
        {
            perror("writeBytesSerialPort failed");
            closeSerialPort();
            return -1;
        }

        // Print sent DISC frame
        printf(GREEN "[Sent] [%s] Rx -> Tx%s\n", "DISC", RESET);
        sleep(1); // Wait for transmission

        // Wait for UA from transmitter
        alarmCount = 0;
        alarmEnabled = FALSE;
        (void)signal(SIGALRM, alarmHandler);
        while (alarmCount < connectionParameters.nRetransmissions)
        {
            if (alarmEnabled == FALSE)
            {
                alarm(connectionParameters.timeout);
                alarmEnabled = TRUE;

                enum CloseStates state = CLOSE_START;
                unsigned char response_ua[5] = {0};

                while (alarmEnabled == TRUE && state != CLOSE_STOP)
                {
                    int bytesRead = readByteSerialPort(&readChar);
                    if (bytesRead == -1)
                    {
                        perror("readByteSerialPort failed");
                        closeSerialPort();
                        return -1;
                    }
                    else if (bytesRead == 0)
                    {
                        continue; // No byte read, continue waiting
                    }

                    // Process UA response byte by byte
                    switch (state)
                    {
                    case CLOSE_START:
                        if (readChar == FLAG)
                            state = CLOSE_FLAG_OK;
                        break;
                    case CLOSE_FLAG_OK:
                        if (readChar == A_Tx)
                        {
                            state = CLOSE_ADDR_OK;
                            response_ua[1] = readChar;
                        }
                        else if (readChar != FLAG)
                        {
                            state = CLOSE_START;
                        }
                        break;
                    case CLOSE_ADDR_OK:
                        if (readChar == FLAG)
                        {
                            state = CLOSE_FLAG_OK;
                        }
                        else if (readChar == UA)
                        {
                            state = CLOSE_CTRL_OK;
                            response_ua[2] = readChar;
                        }
                        else
                        {
                            state = CLOSE_START;
                        }
                        break;
                    case CLOSE_CTRL_OK:
                        if (readChar == (response_ua[1] ^ response_ua[2]))
                        {
                            state = CLOSE_BCC_OK;
                            response_ua[3] = readChar;
                        }
                        else if (readChar == FLAG)
                        {
                            state = CLOSE_FLAG_OK;
                        }
                        else
                        {
                            state = CLOSE_START;
                        }
                        break;
                    case CLOSE_BCC_OK:
                        if (readChar == FLAG)
                        {
                            response_ua[4] = FLAG;
                            state = CLOSE_STOP;
                        }
                        else
                        {
                            state = CLOSE_START;
                        }
                        break;
                    default:
                        break;
                    }
                }

                if (state == CLOSE_STOP)
                {
                    // Print received UA frame
                    printf(GREEN "[Received] [%s] Rx -> Tx%s\n", "UA", RESET);
                    break; // UA received successfully
                }
            }
        }

        // Restore terminal settings and close the port
        if (closeSerialPort() < 0)
        {
            perror("closeSerialPort failed");
            return -1;
        }

        return 1; // Disconnection successful
    }
}
