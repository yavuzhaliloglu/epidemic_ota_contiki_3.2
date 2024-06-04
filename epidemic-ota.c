#include "contiki.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "net/rpl/rpl.h"
#include "sys/node-id.h"
#include "net/ip/uip-udp-packet.h"
#include "simple-udp.h"
#include "net/rpl/rpl-private.h"
#include "sys/etimer.h"
#include "sys/ctimer.h"
#include "crc32.h"

#include "dev/flash.h"
#include "dev/rom-util.h"
#include "dev/watchdog.h"
#include "epidemic-ota.h"

/*----------------------------------------------------------------Defines----*/

// TODO: paket yollanma esnasında update process timer'ı durdurulacak
#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define TEST_CLIENT 1

#define UDP_PORT 1234
#define FLASH_OTA_INFO_ADDR OTA_SYS_ADDR
#define FLASH_OTA_BITMAP_ADDR OTA_SYS_ADDR + FLASH_PAGE_SIZE
#define FLASH_OTA_DATA_ADDR OTA_SYS_ADDR + (2 * FLASH_PAGE_SIZE)

#if TSCH_TIME_SYNCH
#include "net/rpl/rpl-private.h"
#include "net/mac/4emac/4emac-private.h"
#include "net/mac/4emac/4emac-buf.h"
#include "net/mac/4emac/6top-pce/nbr-cell-table.h"
#endif

/*--------------------------------------------------------------Variables----*/

static struct simple_udp_connection udp_conn;               // UDP connection variable
static uip_ipaddr_t *parent_ip_address;                     // Parent IP address
static enum device_state ota_process_state = STATE_REQUEST; // Device ota_process_state
static uint8_t ota_cell_num = 0;                            // Current ota process activated node count
static uip_ipaddr_t updating_device_list[MAX_OTA_CELL];     // current updating device list
static struct ota_info current_ota_info;                    // current ota info
static struct ota_info last_ota_info;                       // last ota info
static struct ctimer update_state_timer;                    // update state callback timer
static uint16_t current_ota_fragnum;                        // current fragnum for ota
process_event_t state_request_event;                        // request event variable
static uint8_t is_ota_to_keep;

/*--------------------------------------------------------------Processes----*/

PROCESS(request_process, "Epidemic Routing Request Process");
PROCESS(update_process, "Epidemic Routing Update Process");
PROCESS(test_flash_process, "Flash Process For Testing");

AUTOSTART_PROCESSES(&test_flash_process);

/*--------------------------------------------------------------Functions----*/

// FLASH OPERATIONS
unsigned int ota_arch_flash_addr();
unsigned int ota_arch_flash_size();
void ota_arch_erase(unsigned int addr, unsigned int size);
void ota_arch_write(const void *buf, unsigned int addr, unsigned int size);
void ota_arch_read(void *buf, unsigned int flash_addr, unsigned int size);
void ota_arch_init();

// print a buffer as hexadecimals
static void printBufferHex(uint8_t *buffer, uint16_t len)
{
    if (DEBUG)
    {
        for (uint16_t i = 0; i < len; i++)
        {
            if (i % 16 == 0 && i != 0)
            {
                printf("\n");
                if (i % 256 == 0)
                    printf("\n");
            }

            PRINTF("%02X ", buffer[i]);
        }
    }
}

// print packet status
static void print_packet_status(struct ota_packet *p)
{
    PRINTF("PRINT_PACKET_STATUS: Packet Status: \n");

    PRINTF("PRINT_PACKET_STATUS: p->msg_type: %02X\n", p->msg_type);
    PRINTF("PRINT_PACKET_STATUS: p->fw_version: %ld\n", p->fw_version);

    if (p->msg_type == OTA_REQUEST)
        PRINTF("PRINT_PACKET_STATUS: p->is_new_ota: %d\n", p->is_new_ota);
    if (p->msg_type == OTA_RESPONSE)
        PRINTF("PRINT_PACKET_STATUS: p->fw_size: %ld\n", p->fw_size);
    if (p->msg_type == OTA_RESPONSE || p->msg_type == OTA_PACKET_REQUEST || p->msg_type == OTA_DATA_PACKET)
        PRINTF("PRINT_PACKET_STATUS: p->fw_fragment_num: %d\n", p->fw_fragment_num);
    if (p->msg_type == OTA_RESPONSE)
        PRINTF("PRINT_PACKET_STATUS: p->fw_fragment_size: %d\n", p->fw_fragment_size);
    if (p->msg_type == OTA_RESPONSE)
        PRINTF("PRINT_PACKET_STATUS: p->crc: %ld\n", p->crc);
    if (p->msg_type == OTA_RESPONSE)
    {
        PRINTF("PRINT_PACKET_STATUS: p->blacklist nodes: \n");
        printBufferHex((uint8_t *)p->blacklist_nodes, sizeof(uip_ipaddr_t) * MAX_BLACKLIST_NODES);
    }
    if (p->msg_type == OTA_DATA_PACKET)
    {
        PRINTF("PRINT_PACKET_STATUS: p->data->len: %d\n", p->data.len);
        PRINTF("PRINT_PACKET_STATUS: p->data->buf:\n");
        printBufferHex(p->data.buf, p->data.len);
        PRINTF("\n");
    }
}

static void print_ota_info_packet_status(struct ota_info *p)
{
    PRINTF("PRINT_OTA_INFO_PACKET_STATUS: p->fw_version: %ld\n", p->fw_version);
    PRINTF("PRINT_OTA_INFO_PACKET_STATUS: p->crc: %ld\n", p->crc);
    PRINTF("PRINT_OTA_INFO_PACKET_STATUS: p->fw_size: %ld\n", p->fw_size);
    PRINTF("PRINT_OTA_INFO_PACKET_STATUS: p->fw_fragment_num: %d\n", p->fw_fragment_num);
    PRINTF("PRINT_OTA_INFO_PACKET_STATUS: p->fw_fragment_size: %d\n", p->fw_fragment_size);
    PRINTF("PRINT_OTA_INFO_PACKET_STATUS: p->blacklist_nodes: \n");
    for (int i = 0; i < MAX_BLACKLIST_NODES; i++)
    {
        printf("IP Address %d: ", i);
        uip_debug_ipaddr_print(&p->blacklist_nodes[i]);
        printf("\n");
    }
    PRINTF("\n");
}

// reverses 1 byte's bits
static uint8_t reverseBits(uint8_t byte)
{
    uint8_t reversed = 0;
    for (int i = 0; i < 8; i++)
    {
        if (byte & (1 << i))
        {
            reversed |= 1 << (7 - i);
        }
    }
    return reversed;
}

// finds zero bit in a byte
static int8_t findZeroBit(uint8_t byte)
{
    for (int8_t i = 7; i >= 0; i--)
    {
        if (((byte >> i) & 1) == 0)
        {
            return 7 - i; // Found a 0 bit
        }
    }
    return -1; // No 0 bit found
}

// sets bit in given index
static void setBit(uint8_t *word, uint16_t index)
{
    uint8_t byteIndex = index / 8;
    uint8_t bitIndex = index % 8;

    uint8_t mask = 1 << (7 - bitIndex);

    word[byteIndex] |= mask;
}

void convert_to_global_unicast(uip_ipaddr_t *global_addr, uip_ipaddr_t *link_local_addr)
{
    // Copy the link-local address to the global address
    memcpy(global_addr, link_local_addr, sizeof(uip_ipaddr_t));

    // Set the global prefix (e.g., 2001:db8::/64)
    global_addr->u8[0] = 0xfd;
    global_addr->u8[1] = 0x00;
    global_addr->u8[2] = 0x00;
    global_addr->u8[3] = 0x00;

    // Ensure the rest of the global address is correct (e.g., set the right subnet if necessary)
    // This part can be customized based on your specific network requirements.
}

// reads firmware data from given fragnum index as fragsize bytes
static void get_firmware_data(uint8_t *buf, uint16_t fragnum, uint8_t fragsize)
{
    ota_arch_read(buf, FLASH_OTA_DATA_ADDR + (fragnum * fragsize), fragsize);

    PRINTF("SEND_FIRMWARE_PACKET: data read from flash. Read data is:\n");
    printBufferHex(buf, fragsize);
    PRINTF("\n");
}

// Function to add an IP address to the list
void add_ip_to_list(uip_ipaddr_t *list, uip_ipaddr_t *new_ip, uint8_t *list_size)
{
    if (*list_size < MAX_OTA_CELL)
    {
        list[*list_size] = *new_ip;
        (*list_size)++;
    }
    else
    {
        printf("IP address list is full!\n");
    }
}

// finds first 0 bit in bitmap and returns index of that bit
static int find_packet_number(struct ota_info *p)
{
    uint8_t bitmap_word_buf[FLASH_WORD_SIZE];
    uint16_t current_ota_bitmap_length = p->fw_fragment_num;
    uint16_t word_index = 0;
    uint8_t byte_index = 0;
    int8_t bit_index = 0;
    uint16_t packet_num = 0;
    uint8_t bit_found_flag = 0;

    while (word_index <= (current_ota_bitmap_length / (FLASH_WORD_SIZE * 8)))
    {
        ota_arch_read(bitmap_word_buf, FLASH_OTA_BITMAP_ADDR + (word_index * FLASH_WORD_SIZE), FLASH_WORD_SIZE);

        for (uint8_t byte_num = 0; byte_num < FLASH_WORD_SIZE; byte_num++)
        {
            bit_index = findZeroBit(bitmap_word_buf[byte_num]);
            if (bit_index >= 0)
            {
                byte_index = byte_num;
                bit_found_flag = 1;
                break;
            }

            watchdog_periodic();
        }

        if (bit_found_flag)
        {
            break;
        }

        word_index++;
        watchdog_periodic();
    }

    if (bit_index == -1)
    {
        PRINTF("FIND_PACKET_NUMBER: Packet cannot found in bitmap.\n");
        return -1;
    }

    packet_num = (word_index * FLASH_WORD_SIZE * 8) + (byte_index * 8) + bit_index;

    return packet_num;
}

// controls bitmap if there is any 0 bit. If 0 bit exists returns 0, if not returns 1
static uint8_t is_bitmap_full()
{
    int is_packet_found = find_packet_number(&last_ota_info);

    if (is_packet_found >= 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

// compare this firmware version with given firmware version, if this firmware version is newer return 1, if older or equal return 0
static uint8_t compare_firmware_version(uint32_t fw_version)
{
    if (last_ota_info.fw_version < fw_version)
    {
        PRINTF("COMPARE_FIRMWARE_VERSION: this firmware version is older than incoming firmware version.\n");
        return 0;
    }
    else if (last_ota_info.fw_version == fw_version)
    {
        PRINTF("COMPARE_FIRMWARE_VERSION: this firmware version and incoming firmware version is euqal.\n");
        return 1;
    }
    else
    {
        PRINTF("COMPARE_FIRMWARE_VERSION: this firmware version is newer than incoming firmware version.\n");
        return 2;
    }
}

// returns index of ip address in update device list
static uint8_t find_address_index_in_updating_device_list(uip_ipaddr_t *ipaddr)
{
    uint8_t list_idx = 0;

    while (list_idx < MAX_OTA_CELL)
    {
        if (uip_ip6addr_cmp(&updating_device_list[list_idx], ipaddr))
        {
            PRINTF("FIND_ADDRESS_INDEX_IN_UPDATE_DEVICE_LIST: This device is already in updating list!\n");
            break;
        }

        list_idx++;
    }
    PRINTF("FIND_ADDRESS_INDEX_IN_UPDATE_DEVICE_LIST: This device is not in updating list!\n");
    return list_idx;
}

// clears content of updating device list array
static void clear_updating_device_list()
{
    uint8_t lst_idx = 0;

    for (lst_idx = 0; lst_idx < MAX_OTA_CELL; lst_idx++)
    {
        uip_create_unspecified(&updating_device_list[lst_idx]);
    }

    PRINTF("CLEAR_UPDATING_DEVICE_LIST: All entries have been cleaned.\n");
}

// removes an ip address from updating device list
static uint8_t remove_ipaddr_from_updating_device_list(uip_ipaddr_t *ipaddr)
{
    uint8_t lst_idx = 0;

    while (lst_idx < MAX_OTA_CELL)
    {
        if (uip_ip6addr_cmp(&updating_device_list[lst_idx], ipaddr))
        {
            PRINTF("REMOVE_IPADDR_FROM_UPDATING_DEVICE_LIST: This address is in updating list!\n");

            // Move the last element to the current position
            if (lst_idx != MAX_OTA_CELL - 1)
            {
                updating_device_list[lst_idx] = updating_device_list[MAX_OTA_CELL - 1];
            }

            // Clear the last element (optional but recommended)
            uip_create_unspecified(&updating_device_list[MAX_OTA_CELL - 1]);

            PRINTF("REMOVE_IPADDR_FROM_UPDATING_DEVICE_LIST: removing process completed.\n");
            return 1;
        }

        lst_idx++;
    }

    PRINTF("REMOVE_IPADDR_FROM_UPDATING_DEVICE_LIST: This address cannot be found in the updating list!\n");
    return 0;
}

// create a request content buffer (add msg type and firmware version only)
static uint8_t prepare_ota_request_packet(struct ota_packet *p, uint8_t msg_type)
{
    // set variables for packet
    p->msg_type = msg_type;
    p->fw_version = last_ota_info.fw_version;
    p->is_new_ota = is_bitmap_full();

    if (p->msg_type && p->fw_version && (p->is_new_ota == 1 || p->is_new_ota == 0))
    {
        return 1;
    }

    PRINTF("PREPARE_OTA_REQUEST_PACKET: Preparing REQUEST packet is failed!\n");
    return 0;
}

// create a response content buffer (add msg type, firmware version, firmware size, firmware fragment number, firmware fragment size and crc(in the ota data field) only)
static uint8_t prepare_ota_response_packet(struct ota_packet *p, uint8_t msg_type)
{
    p->msg_type = msg_type;
    p->fw_version = last_ota_info.fw_version;
    p->fw_size = last_ota_info.fw_size;
    p->fw_fragment_num = (last_ota_info.fw_size % OTA_MAX_DATA_SIZE) == 0 ? (last_ota_info.fw_size / OTA_MAX_DATA_SIZE) : (last_ota_info.fw_size / OTA_MAX_DATA_SIZE) + 1;
    p->fw_fragment_size = OTA_MAX_DATA_SIZE;
    p->crc = last_ota_info.crc;
    memcpy(&p->blacklist_nodes, &last_ota_info.blacklist_nodes, (sizeof(uip_ipaddr_t) * MAX_BLACKLIST_NODES));

    if (p->msg_type && p->fw_version && p->fw_size && p->fw_fragment_num && p->fw_fragment_size && p->crc)
    {
        return 1;
    }

    PRINTF("PREPARE_OTA_RESPONSE_PACKET: Preparing RESPONSE packet is failed!\n");
    return 0;
}

// create a packet request content buffer
static uint8_t prepare_ota_packet_request_packet(struct ota_packet *p, uint8_t msg_type)
{
    int packet_number_returned_bitmap = find_packet_number(&current_ota_info);
    uint16_t packet_num;

    if (packet_number_returned_bitmap >= 0)
    {
        packet_num = (uint16_t)packet_number_returned_bitmap;

        p->msg_type = msg_type;
        p->fw_version = current_ota_info.fw_version;
        p->fw_fragment_num = packet_num;

        if (p->msg_type && p->fw_version && p->fw_fragment_num >= 0 && p->fw_fragment_num <= current_ota_info.fw_fragment_num)
        {
            return 1;
        }
        else
        {
            PRINTF("PREPARE_OTA_PACKET_REQUEST_PACKET: Packet CANNOT created!\n");
            return 0;
        }
    }
    else
    {
        PRINTF("PREPARE_OTA_PACKET_REQUEST_PACKET: Bitmap is full! there is no packet to request!\n");
        return 0;
    }
}

// create a data packet content buffer
static uint8_t prepare_ota_data_packet(struct ota_packet *p, uint8_t msg_type)
{
    uint8_t buf[OTA_MAX_DATA_SIZE];
    get_firmware_data(buf, current_ota_fragnum, current_ota_info.fw_fragment_size);

    p->msg_type = msg_type;
    p->fw_version = current_ota_info.fw_version;
    p->fw_fragment_num = current_ota_fragnum;
    memcpy(p->data.buf, buf, current_ota_info.fw_fragment_size);
    p->data.len = current_ota_info.fw_fragment_size;

    // TODO: data kontrolü de ekle
    if (p->msg_type && p->fw_version && p->fw_fragment_num >= 0 && p->fw_fragment_num <= current_ota_info.fw_fragment_num)
    {
        return 1;
    }
    else
    {
        PRINTF("Packet CANNOT Created!\n");
        return 0;
    }
}

// prepare a packet with given data and modes, it returns 0 if the preparing packet is failed, returns 1 if preparing packet is successful
static uint8_t prepare_ota_packet(struct ota_packet *p, uint8_t msg_type)
{
    uint8_t is_packet_prepared;

    switch (msg_type)
    {
    case OTA_REQUEST:
        is_packet_prepared = prepare_ota_request_packet(p, msg_type);
        break;

    case OTA_RESPONSE:
        is_packet_prepared = prepare_ota_response_packet(p, msg_type);
        break;

    case OTA_PACKET_REQUEST:
        is_packet_prepared = prepare_ota_packet_request_packet(p, msg_type);
        break;

    case OTA_DATA_PACKET:
        is_packet_prepared = prepare_ota_data_packet(p, msg_type);
        break;

    default:
        PRINTF("PREPARE_OTA_PACKET: Unsupported message type!\n");
        is_packet_prepared = 0;
        break;
    }

    if (is_packet_prepared)
    {
        return 1;
    }
    PRINTF("PREPARE_OTA_PACKET:packet cannot created!\n");
    return 0;
}

// create packet, transfer packet data into given buffer, it returns 0 if the preparing packet is failed, returns 1 if preparing packet is successful
static uint8_t create_ota_packet(uint8_t *buf, uint8_t len, struct ota_packet *p)
{
    uint8_t cur_len = 0;

    // add message type to packet
    if ((len - cur_len) >= 1)
    {
        buf[cur_len] = p->msg_type;
        cur_len++;
    }
    else
    {
        PRINTF("CREATE_OTA_PACKET: Message Type cannot added packet!\n");
        return 0;
    }

    // add firmware version to packet
    if ((len - cur_len) >= sizeof(uint32_t))
    {
        memcpy(&buf[cur_len], &p->fw_version, sizeof(uint32_t));
        cur_len += sizeof(uint32_t);
    }
    else
    {
        PRINTF("CREATE_OTA_PACKET: Firmware version cannot added packet!\n");
        return 0;
    }

    if (p->msg_type == OTA_REQUEST)
    {
        if ((len - cur_len) >= 1)
        {
            buf[cur_len] = p->is_new_ota;
            cur_len++;
        }
        else
        {
            PRINTF("CREATE_OTA_PACKET: is_new_ota cannot added packet!\n");
            return 0;
        }
    }

    if (p->msg_type == OTA_RESPONSE)
    {
        // add firmware size to packet
        if ((len - cur_len) >= sizeof(uint32_t))
        {
            memcpy(&buf[cur_len], &p->fw_size, sizeof(uint32_t));
            cur_len += sizeof(uint32_t);
        }
        else
        {
            PRINTF("CREATE_OTA_PACKET: Firmware size cannot added packet!\n");
            return 0;
        }
    }

    if (p->msg_type == OTA_RESPONSE || p->msg_type == OTA_PACKET_REQUEST || p->msg_type == OTA_DATA_PACKET)
    {
        // add firmware's total fragment number to packet
        if ((len - cur_len) >= sizeof(uint16_t))
        {
            memcpy(&buf[cur_len], &p->fw_fragment_num, sizeof(uint16_t));
            cur_len += sizeof(uint16_t);
        }
        else
        {
            PRINTF("CREATE_OTA_PACKET: Firmware's total fragment number cannot added packet!\n");
            return 0;
        }
    }

    if (p->msg_type == OTA_RESPONSE)
    {
        // add firmware's fragment size to packet
        if ((len - cur_len) >= 1)
        {
            buf[cur_len] = p->fw_fragment_size;
            cur_len++;
        }
        else
        {
            PRINTF("CREATE_OTA_PACKET: Firmware fragment size cannot added packet!\n");
            return 0;
        }
    }

    if (p->msg_type == OTA_RESPONSE)
    {
        if ((len - cur_len) >= sizeof(uint32_t))
        {
            memcpy(&buf[cur_len], &p->crc, sizeof(uint32_t));
            cur_len += sizeof(uint32_t);
        }
        else
        {
            PRINTF("CREATE_OTA_PACKET: Firmware crc cannot added packet!\n");
            return 0;
        }
    }

    if (p->msg_type == OTA_RESPONSE)
    {
        if ((len - cur_len) >= sizeof(uip_ipaddr_t) * MAX_BLACKLIST_NODES)
        {
            memcpy(&buf[cur_len], &p->blacklist_nodes, sizeof(uip_ipaddr_t) * MAX_BLACKLIST_NODES);
            cur_len += sizeof(uip_ipaddr_t) * MAX_BLACKLIST_NODES;
        }
        else
        {
            PRINTF("CREATE_OTA_PACKET: Firmware blacklist nodes cannot added packet!\n");
            return 0;
        }
    }

    if (p->msg_type == OTA_DATA_PACKET)
    {
        // add firmware data len to packet
        if ((len - cur_len) >= 1)
        {
            buf[cur_len] = p->data.len;
            cur_len++;
        }
        else
        {
            PRINTF("CREATE_OTA_PACKET: Firmware data len cannot added packet!\n");
            return 0;
        }
    }

    if (p->msg_type == OTA_DATA_PACKET)
    {
        // add firmware data to packet
        if ((len - cur_len) >= p->data.len)
        {
            memcpy(&buf[cur_len], &p->data.buf, p->data.len);
            cur_len += p->data.len;
        }
        else
        {
            PRINTF("CREATE_OTA_PACKET: Firmware data buf cannot added packet!\n");
            return 0;
        }
    }

    return cur_len;
}

// creates a buffer that contains ota info packet data
static uint8_t create_ota_info_buffer(uint8_t *buf, uint8_t len, struct ota_info *p)
{
    uint8_t cur_len = 0;

    if ((len - cur_len) >= sizeof(uint32_t))
    {
        memcpy(&buf[cur_len], &p->fw_version, sizeof(uint32_t));
        cur_len += sizeof(uint32_t);
    }
    else
    {
        PRINTF("CREATE_OTA_INFO_PACKET: Firmware version cannot added packet!\n");
        return 0;
    }

    if ((len - cur_len) >= sizeof(uint32_t))
    {
        memcpy(&buf[cur_len], &p->crc, sizeof(uint32_t));
        cur_len += sizeof(uint32_t);
    }
    else
    {
        PRINTF("CREATE_OTA_INFO_PACKET: Firmware CRC cannot added packet!\n");
        return 0;
    }

    if ((len - cur_len) >= sizeof(uint32_t))
    {
        memcpy(&buf[cur_len], &p->fw_size, sizeof(uint32_t));
        cur_len += sizeof(uint32_t);
    }
    else
    {
        PRINTF("CREATE_OTA_INFO_PACKET: Firmware Size cannot added packet!\n");
        return 0;
    }

    if ((len - cur_len) >= sizeof(uint16_t))
    {
        memcpy(&buf[cur_len], &p->fw_fragment_num, sizeof(uint16_t));
        cur_len += sizeof(uint16_t);
    }
    else
    {
        PRINTF("CREATE_OTA_INFO_PACKET: Firmware fragment number cannot added packet!\n");
        return 0;
    }

    if ((len - cur_len) >= 1)
    {
        buf[cur_len] = p->fw_fragment_size;
        cur_len++;
    }
    else
    {
        PRINTF("CREATE_OTA_INFO_PACKET: Firmware fragment size cannot added packet!\n");
        return 0;
    }

    if ((len - cur_len) >= sizeof(uip_ipaddr_t) * MAX_BLACKLIST_NODES)
    {
        memcpy(&buf[cur_len], &p->blacklist_nodes, sizeof(uip_ipaddr_t) * MAX_BLACKLIST_NODES);
        cur_len += sizeof(uip_ipaddr_t) * MAX_BLACKLIST_NODES;
    }
    else
    {
        PRINTF("CREATE_OTA_INFO_PACKET: Firmware fragment size cannot added packet!\n");
        return 0;
    }

    return cur_len;
}

static struct ota_packet ota_parse_buf(uint8_t *buf, uint16_t len)
{
    uint16_t cur_len = 0;
    struct ota_packet p;

    if ((len - cur_len) >= 1)
    {
        p.msg_type = buf[cur_len];
        cur_len++;
    }

    if ((len - cur_len) >= sizeof(uint32_t))
    {
        memcpy(&p.fw_version, &buf[cur_len], sizeof(uint32_t));
        cur_len += sizeof(uint32_t);
    }

    if (p.msg_type == OTA_REQUEST)
    {
        if ((len - cur_len) >= 1)
        {
            p.is_new_ota = buf[cur_len];
            cur_len++;
        }
    }

    if (p.msg_type == OTA_RESPONSE)
    {
        if ((len - cur_len) >= sizeof(uint32_t))
        {
            memcpy(&p.fw_size, &buf[cur_len], sizeof(uint32_t));
            cur_len += sizeof(uint32_t);
        }
    }

    if (p.msg_type == OTA_RESPONSE || p.msg_type == OTA_PACKET_REQUEST || p.msg_type == OTA_DATA_PACKET)
    {
        if ((len - cur_len) >= sizeof(uint16_t))
        {
            memcpy(&p.fw_fragment_num, &buf[cur_len], sizeof(uint16_t));
            cur_len += sizeof(uint16_t);
        }
    }

    if (p.msg_type == OTA_RESPONSE)
    {
        if ((len - cur_len) >= 1)
        {
            p.fw_fragment_size = buf[cur_len];
            cur_len++;
        }
    }

    if (p.msg_type == OTA_RESPONSE)
    {
        if ((len - cur_len) >= sizeof(uint32_t))
        {
            memcpy(&p.crc, &buf[cur_len], sizeof(uint32_t));
            cur_len += sizeof(uint32_t);
        }
    }

    if (p.msg_type == OTA_RESPONSE)
    {
        if ((len - cur_len) >= (sizeof(uip_ipaddr_t) * MAX_BLACKLIST_NODES))
        {
            memcpy(&p.blacklist_nodes, &buf[cur_len], (sizeof(uip_ipaddr_t) * MAX_BLACKLIST_NODES));
            cur_len += (sizeof(uip_ipaddr_t) * MAX_BLACKLIST_NODES);
        }
    }

    if (p.msg_type == OTA_DATA_PACKET || p.msg_type == OTA_RESPONSE)
    {
        if ((len - cur_len) >= 1)
        {
            p.data.len = buf[cur_len];
            cur_len++;
        }
    }

    if (p.msg_type == OTA_DATA_PACKET || p.msg_type == OTA_RESPONSE)
    {
        if ((len - cur_len) >= p.data.len)
        {
            memcpy(&p.data.buf, &buf[cur_len], p.data.len);
            cur_len += p.data.len;
        }
    }

    return p;
}

static struct ota_info ota_parse_info_buf(uint8_t *buf, uint16_t len)
{
    uint16_t cur_len = 0;
    struct ota_info p;

    if ((len - cur_len) >= sizeof(uint32_t))
    {
        memcpy(&p.fw_version, &buf[cur_len], sizeof(uint32_t));
        cur_len += sizeof(uint32_t);
    }

    if ((len - cur_len) >= sizeof(uint32_t))
    {
        memcpy(&p.crc, &buf[cur_len], sizeof(uint32_t));
        cur_len += sizeof(uint32_t);
    }

    if ((len - cur_len) >= sizeof(uint32_t))
    {
        memcpy(&p.fw_size, &buf[cur_len], sizeof(uint32_t));
        cur_len += sizeof(uint32_t);
    }

    if ((len - cur_len) >= sizeof(uint16_t))
    {
        memcpy(&p.fw_fragment_num, &buf[cur_len], sizeof(uint16_t));
        cur_len += sizeof(uint16_t);
    }

    if ((len - cur_len) >= 1)
    {
        p.fw_fragment_size = buf[cur_len];
        cur_len++;
    }

    if ((len - cur_len) >= (sizeof(uip_ipaddr_t) * MAX_BLACKLIST_NODES))
    {
        memcpy(&p.blacklist_nodes, &buf[cur_len], (sizeof(uip_ipaddr_t) * MAX_BLACKLIST_NODES));
        cur_len += sizeof(uip_ipaddr_t) * MAX_BLACKLIST_NODES;
    }

    return p;
}

static void write_ota_info_to_flash(struct ota_info *p)
{
    uint8_t ota_info_buffer[OTA_INFO_PACKET_SIZE];
    uint8_t response_len = create_ota_info_buffer(ota_info_buffer, OTA_INFO_PACKET_SIZE, p);

    ota_arch_erase(FLASH_OTA_INFO_ADDR, FLASH_PAGE_SIZE);
    ota_arch_write(ota_info_buffer, FLASH_OTA_INFO_ADDR, response_len);
}

static void create_ota_bitmap(uint16_t fw_fragment_num)
{
    // calculate byte size and bit size of bitmap
    uint16_t ota_bitmap_byte_size = fw_fragment_num / 8;
    uint8_t ota_bitmap_remaining_bit_size = fw_fragment_num % 8;

    // calculate buffer size to nearest multiple of 4
    uint16_t buffer_size = (ota_bitmap_byte_size + 1 + 3) & ~3;

    // create a buffer to write bits into flash
    uint8_t fragment_number_buffer[buffer_size];
    uint16_t current_buffer_len = 0;
    // last byte is always 0xff. If number of bits are not multiple of 4, this byte will be changed according to bit count
    uint8_t last_byte_of_ota_bitmap = 0xff;

    // set bytes to 0
    for (current_buffer_len = 0; current_buffer_len < ota_bitmap_byte_size; current_buffer_len++)
    {
        fragment_number_buffer[current_buffer_len] = 0;
        watchdog_periodic();
    }

    // if bit size is not 0 or there are just few packets which has less than 8, set bits of this byte and add to buffer. If bit count is 0, not set the bit, just add to buffer.
    if (ota_bitmap_remaining_bit_size != 0 || current_buffer_len == 0)
    {
        fragment_number_buffer[current_buffer_len] = reverseBits(last_byte_of_ota_bitmap << ota_bitmap_remaining_bit_size);
        current_buffer_len++;
    }
    else
    {
        fragment_number_buffer[current_buffer_len] = last_byte_of_ota_bitmap;
        current_buffer_len++;
    }

    // change 00 paddings to FF
    while (current_buffer_len < buffer_size)
    {
        fragment_number_buffer[current_buffer_len] = 0xFF;
        current_buffer_len++;

        watchdog_periodic();
    }

    // debug bitmap
    PRINTF("BITMAP IS:\n");
    printBufferHex(fragment_number_buffer, current_buffer_len);
    PRINTF("\n");

    // first delete the bitmap, if there is another bitmap from previous OTA operations, and write new bitmap.
    ota_arch_erase(FLASH_OTA_BITMAP_ADDR, FLASH_PAGE_SIZE);
    ota_arch_write(fragment_number_buffer, FLASH_OTA_BITMAP_ADDR, current_buffer_len);
}

static void send_ota_packet(struct ota_packet *p)
{
    uint8_t buf[PACKET_SIZE];
    uint8_t buf_len = 0;

    buf_len = create_ota_packet(buf, PACKET_SIZE, p);

    if (buf_len > 0)
    {
        PRINTF("SEND_PACKET_REQUEST: Packet created. Packet is: \n");
        printBufferHex(buf, buf_len);
        PRINTF("\n");
        PRINTF("SEND_PACKET_REQUEST: Packet is sending to ");
        PRINT6ADDR(parent_ip_address);
        PRINTF("\n");

        // send packet
        simple_udp_sendto(&udp_conn, buf, buf_len, parent_ip_address);
    }
    else
    {
        PRINTF("SEND_PACKET_REQUEST: Packet cannot created!\n");
    }
}

static void copy_ota_info(struct ota_info *dest, struct ota_info *src)
{
    dest->crc = src->crc;
    dest->fw_fragment_num = src->fw_fragment_num;
    dest->fw_fragment_size = src->fw_fragment_size;
    dest->fw_size = src->fw_size;
    dest->fw_version = src->fw_version;
    memcpy(&dest->blacklist_nodes, &src->blacklist_nodes, (sizeof(uip_ipaddr_t) * MAX_BLACKLIST_NODES));
}

// silme kısmı düzeltilecek
static void write_program_data_to_flash(struct ota_packet *p)
{
    if (p->msg_type == OTA_DATA_PACKET && p->fw_fragment_num >= 0 && p->fw_fragment_num < current_ota_info.fw_fragment_num)
    {
        watchdog_periodic();
        uint8_t ota_program_buf[256];
        uint8_t bitmap_buf[FLASH_WORD_SIZE];
        uint16_t bit_num = p->fw_fragment_num;

        // read program area before writing op.
        PRINTF("WRITE_PROGRAM_DATA_TO_FLASH: control passed. Program area before write operation:\n");
        ota_arch_read(ota_program_buf, FLASH_OTA_DATA_ADDR, 256);
        printBufferHex(ota_program_buf, 256);
        PRINTF("\n");

        // write data to flash
        ota_arch_write(p->data.buf, (FLASH_OTA_DATA_ADDR + (p->fw_fragment_num * p->data.len)), p->data.len);

        // read program area after write operation
        ota_arch_read(ota_program_buf, FLASH_OTA_DATA_ADDR, 256);
        PRINTF("WRITE_PROGRAM_DATA_TO_FLASH: Program area after write operation:\n");
        printBufferHex(ota_program_buf, 256);
        PRINTF("\n");

        // read bitmap to change bit
        ota_arch_read(bitmap_buf, FLASH_OTA_BITMAP_ADDR, 256);
        PRINTF("WRITE_PROGRAM_DATA_TO_FLASH: read bitmap. Word is before write op.:\n");
        printBufferHex(bitmap_buf, 256);
        PRINTF("\n");

        // set bit
        setBit(bitmap_buf, bit_num);

        // erase page and write it again
        ota_arch_erase(FLASH_OTA_BITMAP_ADDR, FLASH_PAGE_SIZE);
        ota_arch_write(bitmap_buf, FLASH_OTA_BITMAP_ADDR, 256);

        // read to debug
        ota_arch_read(bitmap_buf, FLASH_OTA_BITMAP_ADDR, 256);
        PRINTF("WRITE_PROGRAM_DATA_TO_FLASH: read bitmap. Word is after write op.:\n");
        printBufferHex(bitmap_buf, 256);
        PRINTF("\n");
    }

    if (p->fw_fragment_num == current_ota_info.fw_fragment_num - 1)
    {
        uint32_t crc = crc32(0, (const void *)FLASH_OTA_DATA_ADDR, current_ota_info.fw_size, 0);
        PRINTF("WRITE_PROGRAM_DATA_TO_FLASH: Calculated CRC is: %ld\n",crc);
        if (crc == current_ota_info.crc)
        {
            PRINTF("WRITE_PROGRAM_DATA_TO_FLASH: CRC true!\n");
        }
        else
        {
            PRINTF("WRITE_PROGRAM_DATA_TO_FLASH: CRC false!\n");
        }
        if (!is_ota_to_keep)
        {
            watchdog_reboot();
        }
    }
}

static void update_ctimer_callback()
{
    PRINTF("Update Ctimer expired!\n");

    if (ota_process_state == STATE_UPDATE_CLIENT)
    {
        copy_ota_info(&last_ota_info, &current_ota_info);
    }
    else
    {
        clear_updating_device_list();
    }

    ota_cell_num = 0;

    ctimer_restart(&update_state_timer);
    ctimer_stop(&update_state_timer);
}

static void start_update_ctimer()
{
    PRINTF("Starting update callback timer...\n");
    ctimer_set(&update_state_timer, PACKET_REQUEST_THRESHOLD * CLOCK_SECOND, update_ctimer_callback, NULL);
}

static void reset_update_ctimer()
{
    PRINTF("Resetting update callback timer...\n");
    ctimer_restart(&update_state_timer);
}

static void init_variables()
{
    uint8_t ota_area_buf[256];

    // read previous ota info from flash
    ota_arch_read(ota_area_buf, FLASH_OTA_INFO_ADDR, 256);
    PRINTF("INIT_VARIABLES: OTA info buffer after write operation:\n");
    printBufferHex(ota_area_buf, 256);
    PRINTF("\n");

    last_ota_info = ota_parse_info_buf(ota_area_buf, 256);

    if (last_ota_info.fw_version == 0xffffffff)
    {
        last_ota_info.fw_version = 1;
        last_ota_info.fw_size = 1;
        last_ota_info.fw_fragment_size = 1;
        last_ota_info.fw_fragment_num = 1;
        last_ota_info.crc = 1;
    }

    PRINTF("INIT_VARIABLES: last_ota_info packet status:\n");
    print_ota_info_packet_status(&last_ota_info);
}

static uint8_t is_ota_info_area_empty()
{
    uint8_t ota_area_buf[256];

    // read previous ota info from flash
    ota_arch_read(ota_area_buf, FLASH_OTA_INFO_ADDR, 256);
    PRINTF("TEST_FLASH_PROCESS: OTA info buffer after write operation:\n");
    printBufferHex(ota_area_buf, 256);
    PRINTF("\n");

    last_ota_info = ota_parse_info_buf(ota_area_buf, 256);

    if (last_ota_info.fw_version == 0xffffffff)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

static uint8_t is_this_node_in_blacklist(uip_ipaddr_t *list, uint8_t len, uip_ipaddr_t *receiver_addr)
{
    uip_ipaddr_t receiver_temp;
    uip_ipaddr_copy(&receiver_temp, receiver_addr);
    receiver_temp.u8[0] = 0xfd;
    receiver_temp.u8[1] = 0x00;
    receiver_temp.u8[2] = 0x00;
    receiver_temp.u8[3] = 0x00;

    PRINTF("Receiver Address is: ");
    PRINT6ADDR(&receiver_temp);
    PRINTF("\n");

    for (uint8_t i = 0; i < len; i++)
    {
        PRINTF("IP Address %d: ", i);
        PRINT6ADDR(&list[i]);
        PRINTF("\n");
    }

    for (uint8_t i = 0; i < len; i++)
    {
        if (uip_ip6addr_cmp(&list[i], &receiver_temp))
        {
            PRINTF("IS_THIS_NODE_IN_BLACKLIST: This device is in blacklist!\n");
            return 1;
        }
    }

    PRINTF("IS_THIS_NODE_IN_BLACKLIST: This device is not in blacklist!\n");
    return 0;
}

// UDP connection callback handler
static void
udp_callback(struct simple_udp_connection *c,
             const uip_ipaddr_t *sender_addr,
             uint16_t sender_port,
             const uip_ipaddr_t *receiver_addr,
             uint16_t receiver_port,
             const uint8_t *data,
             uint16_t datalen)
{
    watchdog_periodic();

    PRINTF("\nUDP_CALLBACK: Data received with length %d, from address: ", datalen);
    PRINT6ADDR(sender_addr);
    PRINTF("\n");

    struct ota_packet incoming_packet = ota_parse_buf((uint8_t *)data, datalen);
    struct ota_packet packet_to_send;
    uint8_t buf_to_send[PACKET_SIZE];
    uint8_t buf_len = 0;
    uint8_t list_idx = 0;

    print_packet_status(&incoming_packet);

    switch (incoming_packet.msg_type)
    {
    case OTA_REQUEST:
        PRINTF("UDP_CALLBACK: Incoming packet type is OTA_REQUEST.\n");

        list_idx = find_address_index_in_updating_device_list((uip_ipaddr_t *)sender_addr);

        if (is_bitmap_full() && list_idx >= MAX_OTA_CELL && ota_cell_num < MAX_OTA_CELL && ota_process_state != STATE_UPDATE_CLIENT)
        {
            if (compare_firmware_version(incoming_packet.fw_version) == 2 || (compare_firmware_version(incoming_packet.fw_version) == 1 && incoming_packet.is_new_ota == 0))
            {
                list_idx--;
                add_ip_to_list(updating_device_list, (uip_ipaddr_t *)sender_addr, &list_idx);

                ota_cell_num++;
                copy_ota_info(&current_ota_info, &last_ota_info);
                ota_process_state = STATE_UPDATE_SERVER;

                if (prepare_ota_packet(&packet_to_send, OTA_RESPONSE))
                {
                    buf_len = create_ota_packet(buf_to_send, PACKET_SIZE, &packet_to_send);
                    if (buf_len > 0)
                    {
                        PRINTF("Packet is created. Sending to ");
                        PRINT6ADDR(sender_addr);
                        PRINTF("\n");

                        // send packet
                        simple_udp_sendto(c, buf_to_send, buf_len, sender_addr);
                    }
                }

                start_update_ctimer();
            }
        }

        break;

    case OTA_RESPONSE:
        PRINTF("UDP_CALLBACK: Incoming packet type is OTA_RESPONSE.\n");

        if ((compare_firmware_version(incoming_packet.fw_version) == 0 || (compare_firmware_version(incoming_packet.fw_version) == 1 && !is_bitmap_full())) && ota_process_state == STATE_REQUEST)
        {
            current_ota_info.fw_version = incoming_packet.fw_version;
            current_ota_info.fw_fragment_size = incoming_packet.fw_fragment_size;
            current_ota_info.fw_size = incoming_packet.fw_size;
            current_ota_info.fw_fragment_num = incoming_packet.fw_fragment_num;
            current_ota_info.crc = incoming_packet.crc;
            memcpy(&current_ota_info.blacklist_nodes, &incoming_packet.blacklist_nodes, (sizeof(uip_ipaddr_t) * MAX_BLACKLIST_NODES));

            if (compare_firmware_version(incoming_packet.fw_version) == 0)
            {
                create_ota_bitmap(current_ota_info.fw_fragment_num);        // create bitmap for ota
                ota_arch_erase(FLASH_OTA_DATA_ADDR, last_ota_info.fw_size); // erase last ota data
                write_ota_info_to_flash(&current_ota_info);                 // write ota info to flash
            }

            uint8_t buf_info[64];
            uint8_t buf_bitmap[64];
            ota_arch_read(buf_info, FLASH_OTA_INFO_ADDR, 64);
            ota_arch_read(buf_bitmap, FLASH_OTA_BITMAP_ADDR, 64);

            PRINTF("OTA_INFO AREA BUFFER CONTENT:\n");
            printBufferHex(buf_info, 64);
            PRINTF("\n");

            PRINTF("OTA_BITMAP AREA BUFFER CONTENT:\n");
            printBufferHex(buf_bitmap, 64);
            PRINTF("\n");

            is_ota_to_keep = is_this_node_in_blacklist(current_ota_info.blacklist_nodes, MAX_BLACKLIST_NODES, (uip_ipaddr_t *)receiver_addr);

            start_update_ctimer();
            ota_cell_num++;
            ota_process_state = STATE_UPDATE_CLIENT;
        }
        else
        {
            PRINTF("UDP_CALLBACK: incoming ota info is not correct!\n");
        }
        break;

    case OTA_PACKET_REQUEST:
        PRINTF("UDP_CALLBACK: Incoming packet type is OTA_PACKET_REQUEST.\n");
        reset_update_ctimer();

        // TODO: Paket bilgisinin kontrolü düzeltilecek (current ota kısmı)
        if (compare_firmware_version(incoming_packet.fw_version) && ota_process_state == STATE_UPDATE_SERVER)
        {
            if (find_address_index_in_updating_device_list((uip_ipaddr_t *)sender_addr) < MAX_OTA_CELL)
            {
                remove_ipaddr_from_updating_device_list((uip_ipaddr_t *)sender_addr);
            }

            current_ota_fragnum = incoming_packet.fw_fragment_num;

            if (prepare_ota_packet(&packet_to_send, OTA_DATA_PACKET))
            {
                buf_len = create_ota_packet(buf_to_send, PACKET_SIZE, &packet_to_send);

                if (buf_len > 0)
                {
                    PRINTF("Data Packet Created. Packet is:\n");
                    printBufferHex(buf_to_send, buf_len);
                    PRINTF("\n");

                    PRINTF("Packet is sending to ");
                    PRINT6ADDR(sender_addr);
                    PRINTF("\n");

                    // send packet
                    simple_udp_sendto(c, buf_to_send, buf_len, sender_addr);
                }
            }
        }
        break;

    case OTA_DATA_PACKET:
        PRINTF("UDP_CALLBACK: Incoming packet type is OTA_DATA_PACKET.\n");

        if (ota_process_state == STATE_UPDATE_CLIENT)
        {
            write_program_data_to_flash(&incoming_packet);
            reset_update_ctimer();
        }
        else
        {
            PRINTF("UDP_CALLBACK: State is not STATE_UPDATE_CLIENT!\n");
        }
        break;

    default:
        PRINTF("UDP_cALLBACK: Incoming packet type is invalid!\n");
        break;
    }
}

/*----------------------------------------------------------Thread(Flash)----*/

PROCESS_THREAD(test_flash_process, ev, data)
{
    static struct ota_info ota_info_flash;
    static uint8_t ota_area_buf[256];
    static uint8_t cur_len;
    static uint8_t ota_data[200];
    static uip_ipaddr_t blacklist_nodes[MAX_BLACKLIST_NODES];
    PROCESS_BEGIN();

#if !TEST_CLIENT
    for (uint8_t i = 0; i < 200; i++)
    {
        ota_data[i] = i;
        watchdog_periodic();
    }

    PRINTF("TEST_FLASH_PROCESS: OTA data:\n");
    printBufferHex(ota_data, 200);
    PRINTF("\n");
#else
    for (uint8_t i = 0; i < 100; i++)
    {
        ota_data[i] = i;
        watchdog_periodic();
    }

    PRINTF("TEST_FLASH_PROCESS: OTA data:\n");
    printBufferHex(ota_data, 100);
    PRINTF("\n");
#endif

    // info area debug
    ota_arch_read(ota_area_buf, FLASH_OTA_INFO_ADDR, 256);
    PRINTF("TEST_FLASH_PROCESS: OTA info area BEFORE ERASE:\n");
    printBufferHex(ota_area_buf, 256);
    PRINTF("\n");

    // bitmap area debug
    ota_arch_read(ota_area_buf, FLASH_OTA_BITMAP_ADDR, 256);
    PRINTF("TEST_FLASH_PROCESS: OTA bitmap area BEFORE ERASE:\n");
    printBufferHex(ota_area_buf, 256);
    PRINTF("\n");

    // data area debug
    ota_arch_read(ota_area_buf, FLASH_OTA_DATA_ADDR, 256);
    PRINTF("TEST_FLASH_PROCESS: OTA data area BEFORE ERASE:\n");
    printBufferHex(ota_area_buf, 256);
    PRINTF("\n");

#if !TEST_CLIENT
    ota_info_flash.fw_version = 2;
    ota_info_flash.crc = crc32(0, (const void *)FLASH_OTA_DATA_ADDR, 200, 0);
    ota_info_flash.fw_size = 200;
    ota_info_flash.fw_fragment_num = (ota_info_flash.fw_size % OTA_MAX_DATA_SIZE) == 0 ? (ota_info_flash.fw_size / OTA_MAX_DATA_SIZE) : (ota_info_flash.fw_size / OTA_MAX_DATA_SIZE) + 1;
    ota_info_flash.fw_fragment_size = OTA_MAX_DATA_SIZE;

    uip_ip6addr(&blacklist_nodes[0], UIP_DS6_DEFAULT_PREFIX, 0x0000, 0x0000, 0x0000, 0x0212, 0x4b00, 0x1ccb, 0x1d17);
    uip_ip6addr(&blacklist_nodes[1], UIP_DS6_DEFAULT_PREFIX, 0x0000, 0x0000, 0x0000, 0x0212, 0x4b00, 0x1ccb, 0x1d07);

    PRINTF("TEST_FLASH_PROCESS: blacklist nodes: \n");
    for (int i = 0; i < MAX_BLACKLIST_NODES; i++)
    {
        printf("IP Address %d: ", i);
        uip_debug_ipaddr_print(&blacklist_nodes[i]);
        printf("\n");
    }

    memcpy(&ota_info_flash.blacklist_nodes, &blacklist_nodes, sizeof(uip_ipaddr_t) * MAX_BLACKLIST_NODES);

    PRINTF("TEST_FLASH_PROCESS: ota_info_flash blacklist nodes: \n");
    for (int i = 0; i < MAX_BLACKLIST_NODES; i++)
    {
        printf("IP Address %d: ", i);
        uip_debug_ipaddr_print(&ota_info_flash.blacklist_nodes[i]);
        printf("\n");
    }
#else
    ota_info_flash.fw_version = 1;
    ota_info_flash.crc = crc32(0, (const void *)FLASH_OTA_DATA_ADDR, 100, 0);
    ota_info_flash.fw_size = 100;
    ota_info_flash.fw_fragment_num = (ota_info_flash.fw_size % OTA_MAX_DATA_SIZE) == 0 ? (ota_info_flash.fw_size / OTA_MAX_DATA_SIZE) : (ota_info_flash.fw_size / OTA_MAX_DATA_SIZE) + 1;
    ota_info_flash.fw_fragment_size = OTA_MAX_DATA_SIZE;
#endif

    // check the ota info area and if it's empty, fill with ota_info_flash value
    if (is_ota_info_area_empty())
    {
        PRINTF("TEST_FLASH_PROCESS: ota_info_flash packet status:\n");
        print_ota_info_packet_status(&ota_info_flash);

        // create info buffer and write it into flash
        cur_len = create_ota_info_buffer(ota_area_buf, sizeof(struct ota_info), &ota_info_flash);

        ota_arch_erase(FLASH_OTA_INFO_ADDR, FLASH_PAGE_SIZE);
        ota_arch_write(ota_area_buf, FLASH_OTA_INFO_ADDR, cur_len);
    }

    /*----------------------------------------------------------------------------------------------------------------*/

    ota_arch_erase(FLASH_OTA_DATA_ADDR, FLASH_PAGE_SIZE);
#if !TEST_CLIENT
    ota_arch_write(ota_data, FLASH_OTA_DATA_ADDR, 200);
#else
    ota_arch_write(ota_data, FLASH_OTA_DATA_ADDR, 100);
#endif

    init_variables();

    // ota area debug
    ota_arch_read(ota_area_buf, FLASH_OTA_DATA_ADDR, 256);
    PRINTF("TEST_FLASH_PROCESS: OTA data area read:\n");
    printBufferHex(ota_area_buf, 256);
    PRINTF("\n");

    process_start(&request_process, NULL);
    PROCESS_END();
}

/*--------------------------------------------------------Thread(Request)----*/

PROCESS_THREAD(request_process, ev, data)
{
    static struct etimer et_request;
    static struct etimer et_auth;
    static struct etimer et_allocate;
    static struct ota_packet p;  // init an ota packet
    static rpl_parent_t *parent; // parent

    PROCESS_BEGIN();
    PROCESS_PAUSE();

    // set synch timer and wait until node is synchronized.
    etimer_set(&et_auth, AUTHENTICATION_INTERVAL * CLOCK_SECOND);
    while (!foure_control.authenticated || default_instance == NULL || default_instance->current_dag->preferred_parent == NULL)
    {
        PROCESS_WAIT_UNTIL(etimer_expired(&et_auth));
        etimer_reset(&et_auth);
        PRINTF("waiting to synch...\n");
    }

    // after the synchronization, get parent from default instance and get it's IP address.
    parent = default_instance->current_dag->preferred_parent;
    parent_ip_address = rpl_get_parent_ipaddr(parent);

    PRINTF("Parent: ");
    PRINT6ADDR(parent_ip_address);
    PRINTF("\n");

    etimer_set(&et_allocate, AUTHENTICATION_INTERVAL * CLOCK_SECOND);
    while (nbr_cell_table_get_cell_num((linkaddr_t *)rpl_get_parent_lladdr(default_instance->current_dag->preferred_parent), SLOT_TYPE_TRANSMIT, SLOT_UNLOCK, 0) < 1)
    {
        PROCESS_WAIT_UNTIL(etimer_expired(&et_allocate));
        etimer_reset(&et_allocate);
        PRINTF("waiting to allocate...\n");
    }

    // set the UDP connection with port UDP_PORT, check if the connection is available, if not, exit from process.
    if (!simple_udp_register(&udp_conn, UIP_HTONS(UDP_PORT), NULL, UIP_HTONS(UDP_PORT), udp_callback))
    {
        PRINTF("REQUEST_PROCESS: UDP Connection Error!\n");
        PROCESS_EXIT();
    }

    // set the request timer
    etimer_set(&et_request, REQUEST_SEND_INTERVAL * CLOCK_SECOND);
    while (1)
    {
        PRINTF("REQUEST_PROCESS: HELLO WORLD FROM REQUEST PROCESS\n");
        PROCESS_WAIT_UNTIL(etimer_expired(&et_request));
        etimer_reset(&et_request);

        // control device ota_process_state, if ota_process_state is request, send request to parent
        if (ota_process_state == STATE_REQUEST)
        {
            // prepare request message, control if packet is prepared, if not, dont send packet
            if (prepare_ota_packet(&p, OTA_REQUEST))
            {
                send_ota_packet(&p);
            }
            else
                PRINTF("REQUEST_PROCESS: packet cannot prepared!\n");
        }
        // if ota_process_state is STATE_UPDATE_CLIENT or STATE_UPDATE_SERVER, don't do anything, just wait until ota process ends.
        else if (ota_process_state == STATE_UPDATE_CLIENT || ota_process_state == STATE_UPDATE_SERVER)
        {
            PRINTF("REQUEST_PROCESS: ota_process_state is %02X. state changing...\n", ota_process_state);
            process_start(&update_process, NULL);
            PROCESS_WAIT_EVENT_UNTIL(ev == state_request_event);
            etimer_restart(&et_request);
        }
        // if unsupported state set, yield
        else
        {
            PRINTF("REQUEST_PROCESS: Unsupported state for request process!\n");
        }
    }

    PROCESS_END();
}

/*---------------------------------------------------------Thread(Update)----*/

PROCESS_THREAD(update_process, ev, data)
{
    static struct etimer et_update;
    static struct ota_packet p;

    PROCESS_BEGIN();
    PROCESS_PAUSE();

    etimer_set(&et_update, PACKET_REQUEST_INTERVAL * CLOCK_SECOND);
    while (1)
    {
        if (ota_process_state == STATE_UPDATE_CLIENT)
        {
            PRINTF("UPDATE_PROCESS:state is STATE_UPDATE_CLIENT. Sending packet...\n");
            if (prepare_ota_packet(&p, OTA_PACKET_REQUEST))
            {
                send_ota_packet(&p);
            }
        }
        else if (ota_process_state == STATE_UPDATE_SERVER)
        {
            PRINTF("UPDATE_PROCESS: state is STATE_UPDATE_SERVER. Waiting for packets.\n");
        }
        else
        {
            PRINTF("UPDATE_PROECSS: Invalid Update Process State!\n");
            break;
        }

        if (ota_cell_num == 0)
        {
            break;
        }

        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et_update));
        PRINTF("UPDATE_PROCESS: HELLO WORLD FROM UPDATE PROCESS\n");
        etimer_reset(&et_update);
    }

    ota_process_state = STATE_REQUEST;
    process_post(&request_process, state_request_event, NULL);

    PROCESS_END();
}
/*-------------------------------------------------------------------Init----*/

void start_epidemic_ota()
{
    process_exit(&test_flash_process);
    process_start(&test_flash_process, NULL);
}
