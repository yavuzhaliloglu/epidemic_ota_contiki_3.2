#ifndef EPIDEMIC_OTA_H_
#define EPIDEMIC_OTA_H_

// time interval to send request message
#define REQUEST_SEND_INTERVAL 5
// max data size for OTA data
#define OTA_MAX_DATA_SIZE 64
// enable time synch
#define TSCH_TIME_SYNCH 1
// authenticate interval time
#define AUTHENTICATION_INTERVAL 3
// max number of nodes that a node can update
#define MAX_OTA_CELL 1
// packet request interval time
#define PACKET_REQUEST_INTERVAL 10
// crc size
#define CRC_SIZE 32

// ota message types
enum ota_message_types
{
    OTA_REQUEST = 0x01,
    OTA_RESPONSE = 0X02,
    OTA_PACKET_REQUEST = 0x03,
    OTA_DATA_PACKET = 0x04,
};

// device states
enum device_state
{
    STATE_REQUEST = 0x01,
    STATE_UPDATE_CLIENT = 0X02,
    STATE_UPDATE_SERVER = 0x03,
};

// ota data struct. Contains data len and data itself
struct ota_data
{
    uint8_t len;
    uint8_t buf[OTA_MAX_DATA_SIZE];
};

// ota packet struct, holds message type, message len and message itself
struct ota_packet
{
    uint8_t msg_type;
    uint32_t fw_version;
    uint16_t fw_size;
    uint8_t fw_fragment_num;
    uint8_t fw_fragment_size;
    struct ota_data data;
};

struct current_ota
{
    uint32_t fw_version;
    uint32_t crc;
    uint16_t fw_size;
    uint8_t fw_fragment_num;
    uint8_t fw_fragment_size;
};

#define MAX_PACKET_SIZE 80

#endif