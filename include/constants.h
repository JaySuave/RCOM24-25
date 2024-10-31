// constants.h

#ifndef CONSTANTS_H
#define CONSTANTS_H

#define SET 0x03 
#define DISC 0x0B 
#define UA 0x07//Unnumbered ACK
#define RR(n) 0x05 | (n<<7)//Positive ACK
#define REJ(n) 0x01 |(n<<7)//Negative ACK

#define FLAG 0x7E
#define A_Tx 0x03 //sent by Tx or reply from Rx
#define A_Rx 0x01 //sent by Rx or reply from Tx
//BCC1 A ^ C

#define CONTROL_IFRAME(n) (n<<6)  //Info frame control byte (n=0or1)
//BCC2 Data1 ^ Data2 ^ Data3 ^...

#define ESC 0x7D
#define EXTRA_STUFFS 0x20


enum PacketsControlField
{
   START = 0x02,
   DATA = 0x01,
   END = 0x03
    
};
#define BUF_SIZE 5 //{F,A,C,BCC1,F}
#define DATA_BLOCK_SIZE 250 
#define IBUF_SIZE ((2 * DATA_BLOCK_SIZE) + 6) //data block + control info
#define TRANSMITTER_READ_BUFF_SIZE 5
#define PACKET_SIZE (4 * DATA_BLOCK_SIZE)  //max payload

//STATISTICS TESTING VALUES
#define KMS 10000
#define T_PROP_PER_KM 5 //us - 5 microseconds per km ? check this

#define PROBABILITY_ERROR 5 //percentage of error probability


#endif // CONSTANTS_H
