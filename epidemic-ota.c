#include "contiki.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "epidemic-ota.h"

#include "net/ip/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "simple-udp.h"
#include "net/rpl/rpl-private.h"

#include "dev/flash.h"
#include "dev/rom-util.h"
#include "dev/watchdog.h"

/*----------------------------------------------------------------Defines----*/

#define DEBUG DEBUG_PRINT
#include "net/ip/uip-debug.h"

#define TEST_CLIENT 0

#define UDP_PORT 1234

#if TSCH_TIME_SYNCH
#include "net/mac/4emac/4emac-private.h"
#include "net/mac/4emac/4emac-buf.h"
#endif

/*--------------------------------------------------------------Variables----*/

// UDP connection variable
static struct simple_udp_connection udp_conn;
// Parent IP address
static const uip_ipaddr_t *parent_ip_address;
// Device ota_process_state
static enum device_state ota_process_state = STATE_REQUEST;
// Current ota process activated node count
static uint8_t ota_cell_num = 0;
// current updating device list
static uip_ipaddr_t updating_device_list[MAX_OTA_CELL];
// current ota info
static struct ota_info current_ota_info;
// last ota info
static struct ota_info last_ota_info;

/*--------------------------------------------------------------Functions----*/

// FLASH OPERATIONS
unsigned int ota_arch_flash_addr();
unsigned int ota_arch_flash_size();
void ota_arch_erase(unsigned int addr, unsigned int size);
void ota_arch_write(const void *buf, unsigned int addr, unsigned int size);
void ota_arch_read(void *buf, unsigned int flash_addr, unsigned int size);
void ota_arch_init();

// print a buffer as hexadecimals
void printBufferHex(uint8_t *buffer, uint16_t len)
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

            printf("%02X ", buffer[i]);
        }
    }
}

// print packet status
void print_packet_status(struct ota_packet *p)
{
    PRINTF("PRINT_PACKET_STATUS: Packet Status: \n");

    PRINTF("PRINT_PACKET_STATUS: p->msg_type: %02X\n", p->msg_type);
    PRINTF("PRINT_PACKET_STATUS: p->fw_version: %ld\n", p->fw_version);

    if (p->msg_type == OTA_RESPONSE)
        PRINTF("PRINT_PACKET_STATUS: p->fw_size: %ld\n", p->fw_size);
    if (p->msg_type == OTA_RESPONSE || p->msg_type == OTA_PACKET_REQUEST || p->msg_type == OTA_DATA_PACKET)
        PRINTF("PRINT_PACKET_STATUS: p->fw_fragment_num: %d\n", p->fw_fragment_num);
    if (p->msg_type == OTA_RESPONSE)
        PRINTF("PRINT_PACKET_STATUS: p->fw_fragment_size: %d\n", p->fw_fragment_size);
    if (p->msg_type == OTA_DATA_PACKET || p->msg_type == OTA_RESPONSE)
        PRINTF("PRINT_PACKET_STATUS: p->data->len: %d\n", p->data.len);
    if (p->msg_type == OTA_DATA_PACKET || p->msg_type == OTA_RESPONSE)
        PRINTF("PRINT_PACKET_STATUS: p->data->buf:\n");
    if (p->msg_type == OTA_DATA_PACKET || p->msg_type == OTA_RESPONSE)
        printBufferHex(p->data.buf, p->data.len);

    PRINTF("\n\n");
}

void print_ota_info_packet_status(struct ota_info *p)
{
    PRINTF("PRINT_OTA_INFO_PACKET_STATUS: p->fw_version: %ld\n", p->fw_version);
    PRINTF("PRINT_OTA_INFO_PACKET_STATUS: p->crc: %ld\n", p->crc);
    PRINTF("PRINT_OTA_INFO_PACKET_STATUS: p->fw_size: %ld\n", p->fw_size);
    PRINTF("PRINT_OTA_INFO_PACKET_STATUS: p->fw_fragment_num: %d\n", p->fw_fragment_num);
    PRINTF("PRINT_OTA_INFO_PACKET_STATUS: p->fw_fragment_size: %d\n", p->fw_fragment_size);
}

// print current device state
void get_device_state(enum device_state state)
{
    PRINTF("GET_DEVICE_STATE: Device State is: ");
    switch (state)
    {
    case STATE_REQUEST:
        PRINTF("STATE_REQUEST\n");
        break;
    case STATE_UPDATE_CLIENT:
        PRINTF("STATE_UPDATE_CLIENT\n");
        break;
    case STATE_UPDATE_SERVER:
        PRINTF("STATE_UPDATE_SERVER\n");
        break;
    default:
        PRINTF("State ERROR!\n");
        break;
    }
}

uint32_t get_firmware_version()
{
    return last_ota_info.fw_version;
}

uint16_t get_firmware_size()
{
    return last_ota_info.fw_size;
}

// compare this firmware version with given firmware version, if this firmware version is newer return 1, if older or equal return 0
uint8_t compare_firmware_version(uint32_t fw_version)
{
    if (get_firmware_version() > fw_version)
    {
        PRINTF("COMPARE_FIRMWARE_VERSION: this firmware version is newer than incoming firmware version.\n");
        return 1;
    }
    else
    {
        PRINTF("COMPARE_FIRMWARE_VERSION: this firmware version is older than or equal incoming firmware version.\n");
        return 0;
    }
}

uint8_t check_updating_device_list(uip_ipaddr_t *ipaddr)
{
    for (uint8_t i = 0; i < MAX_OTA_CELL; i++)
    {
        if (uip_ip6addr_cmp(&updating_device_list[i], ipaddr))
        {
            PRINTF("CHECK_UPDATING_DEVICE_LIST: This device is already in updating list!\n");
            return 0;
        }
    }
    PRINTF("CHECK_UPDATING_DEVICE_LIST: This device is not updating. Adding update list.\n");
    return 1;
}

// create a request content buffer (add msg type and firmware version only)
uint8_t prepare_ota_request_packet(struct ota_packet *p, uint8_t msg_type)
{
    // create a buf and
    // uint8_t buf[OTA_MAX_DATA_SIZE];
    PRINTF("PREPARE_OTA_REQUEST_PACKET: preparing REQUEST packet.\n");

    // set variables for packet
    p->msg_type = msg_type;
    p->fw_version = get_firmware_version();

    print_packet_status(p);

    if (p->msg_type && p->fw_version)
    {
        PRINTF("PREPARE_OTA_REQUEST_PACKET: Preparing REQUEST packet is successful.\n");
        return 1;
    }

    PRINTF("PREPARE_OTA_REQUEST_PACKET: Preparing REQUEST packet is failed!\n");
    return 0;
}

// create a response content buffer (add msg type, firmware version, firmware size, firmware fragment number, firmware fragment size and crc(in the ota data field) only)
uint8_t prepare_ota_response_packet(struct ota_packet *p, uint8_t msg_type)
{
    PRINTF("PREPARE_OTA_RESPONSE_PACKET: preparing RESPONSE packet.\n");

    p->msg_type = msg_type;
    p->fw_version = get_firmware_version();
    p->fw_size = get_firmware_size();
    p->fw_fragment_num = (get_firmware_size() / OTA_MAX_DATA_SIZE);
    p->fw_fragment_size = OTA_MAX_DATA_SIZE;

    uint32_t crc = last_ota_info.crc;
    p->data.len = sizeof(crc);
    memcpy(p->data.buf, &crc, p->data.len);

    print_packet_status(p);

    if (p->msg_type && p->fw_version && p->fw_size && p->fw_fragment_num && p->fw_fragment_size && p->data.len)
    {
        PRINTF("PREPARE_OTA_RESPONSE_PACKET: Preparing RESPONSE packet is successful.\n");
        return 1;
    }

    PRINTF("PREPARE_OTA_RESPONSE_PACKET: Preparing RESPONSE packet is failed!\n");
    return 0;
}

// create a packet request content buffer
uint8_t prepare_ota_packet_request_packet(struct ota_packet *p, uint8_t msg_type)
{
    return 1;
}

// create a data packet content buffer
static uint8_t prepare_ota_data_packet(struct ota_packet *p, uint8_t msg_type)
{
    return 1;
}

// prepare a packet with given data and modes, it returns 0 if the preparing packet is failed, returns 1 if preparing packet is successful
static uint8_t prepare_ota_packet(struct ota_packet *p, uint8_t msg_type)
{
    uint8_t is_packet_prepared;
    PRINTF("PREPARE_OTA_PACKET: msg_type: %02X\n", msg_type);

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
uint8_t create_ota_packet(uint8_t *buf, uint8_t len, struct ota_packet *p)
{
    uint8_t cur_len = 0;
    print_packet_status(p);

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
        PRINTF("CREATE_OTA_PACKET: msg type is OTA_RESPONSE. Adding fw fragment size to packet.\n");
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

    if (p->msg_type == OTA_DATA_PACKET || p->msg_type == OTA_RESPONSE)
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

    if (p->msg_type == OTA_DATA_PACKET || p->msg_type == OTA_RESPONSE)
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
        // p.fw_version = reverse_bits_uint32_t(p.fw_version);
        cur_len += sizeof(uint32_t);
    }

    if ((len - cur_len) >= sizeof(uint32_t))
    {
        memcpy(&p.fw_size, &buf[cur_len], sizeof(uint32_t));
        // p.fw_size = reverse_bits_uint16_t(p.fw_size);
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

    if ((len - cur_len) >= 1)
    {
        p.data.len = buf[cur_len];
        cur_len++;
    }

    if ((len - cur_len) >= p.data.len)
    {
        memcpy(&p.data.buf, &buf[cur_len], p.data.len);
        cur_len += p.data.len;
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
        // p.fw_version = reverse_bits_uint32_t(p.fw_version);
        cur_len += sizeof(uint32_t);
    }

    if ((len - cur_len) >= sizeof(uint32_t))
    {
        memcpy(&p.crc, &buf[cur_len], sizeof(uint32_t));
        // p.fw_size = reverse_bits_uint16_t(p.fw_size);
        cur_len += sizeof(uint32_t);
    }

    if ((len - cur_len) >= sizeof(uint32_t))
    {
        memcpy(&p.fw_size, &buf[cur_len], sizeof(uint32_t));
        // p.fw_size = reverse_bits_uint16_t(p.fw_size);
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

    return p;
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
    PRINTF("\nUDP_CALLBACK: Data received on port %d from port %d with length %d, from address: ", receiver_port, sender_port, datalen);
    PRINT6ADDR(sender_addr);
    PRINTF("\n");
    PRINTF("UDP_CALLBACK: Incoming data buffer is: \n");
    printBufferHex((uint8_t *)data, datalen);
    PRINTF("\n");

    struct ota_packet incoming_packet = ota_parse_buf((uint8_t *)data, datalen);
    struct ota_packet packet_to_send;
    uint8_t buf_to_send[MAX_PACKET_SIZE];
    uint8_t buf_len = 0;

    print_packet_status(&incoming_packet);

    switch (incoming_packet.msg_type)
    {
    case OTA_REQUEST:
        PRINTF("UDP_CALLBACK: Incoming packet type is OTA_REQUEST.\n");

        if (compare_firmware_version(incoming_packet.fw_version) && ota_cell_num < MAX_OTA_CELL && check_updating_device_list((uip_ipaddr_t *)sender_addr))
        {
            PRINTF("UDP_CALLBACK: Starting OTA...\n");

            if (prepare_ota_packet(&packet_to_send, OTA_RESPONSE))
            {
                buf_len = create_ota_packet(buf_to_send, MAX_PACKET_SIZE, &packet_to_send);
                if (buf_len > 0)
                {
                    PRINTF("Packet is created. Sending to ");
                    PRINT6ADDR(sender_addr);
                    PRINTF("\n");

                    // send packet
                    simple_udp_sendto(c, buf_to_send, buf_len, sender_addr);

                    ota_cell_num++;
                    ota_process_state = STATE_UPDATE_SERVER;
                }
            }
        }

        break;

    case OTA_RESPONSE:
        PRINTF("UDP_CALLBACK: Incoming packet type is OTA_RESPONSE.\n");
        uint8_t is_ota_info_correct = incoming_packet.fw_size / incoming_packet.fw_fragment_size == incoming_packet.fw_fragment_num ? 1 : 0;
        if (!compare_firmware_version(incoming_packet.fw_version) && is_ota_info_correct && ota_process_state == STATE_REQUEST)
        {
            current_ota_info.fw_version = incoming_packet.fw_version;
            current_ota_info.fw_fragment_size = incoming_packet.fw_fragment_size;
            current_ota_info.fw_size = incoming_packet.fw_size;
            current_ota_info.fw_fragment_num = incoming_packet.fw_fragment_num;
            current_ota_info.crc = (uint32_t)incoming_packet.data.buf[0];

            print_ota_info_packet_status(&current_ota_info);

            ota_process_state = STATE_UPDATE_CLIENT;
        }
        else
        {
            PRINTF("UDP_CALLBACK: incoming ota info is not correct!\n");
        }
        break;

    case OTA_PACKET_REQUEST:
        PRINTF("UDP_CALLBACK: Incoming packet type is OTA_PACKET_REQUEST.\n");

        break;

    case OTA_DATA_PACKET:
        PRINTF("UDP_CALLBACK: Incoming packet type is OTA_DATA_PACKET.\n");
        break;

    default:
        PRINTF("UDP_cALLBACK: Incoming packet type is invalid!\n");
        break;
    }
}

/*--------------------------------------------------------------Processes----*/

PROCESS(request_process, "Epidemic Routing Request Process");
PROCESS(update_process, "Epidemic Routing Update Process");
PROCESS(test_flash_process, "Flash Process For Testing");
/*----------------------------------------------------------Thread(Flash)----*/

PROCESS_THREAD(test_flash_process, ev, data)
{
    static int flash_addr;
    static int flash_size;
    static struct ota_info ota_info_flash;
    static uint8_t ota_area_buf[256];
    static uint8_t ota_write_buf[256];
    static uint8_t ota_data[128];
    uint8_t cur_len;

    PROCESS_BEGIN();

    for (uint8_t i = 0; i < 128; i++)
    {
        ota_data[i] = i;
        watchdog_periodic();
    }

    flash_addr = ota_arch_flash_addr();
    flash_size = ota_arch_flash_size();

    PRINTF("TEST_FLASH_PROCESS: start addr 0x%x\n", flash_addr);
    PRINTF("TEST_FLASH_PROCESS: flash size %u\n", flash_size);
    PRINTF("TEST_FLASH_PROCESS: OTA data:\n");
    printBufferHex(ota_data, 128);
    PRINTF("\n");

    ota_arch_erase(flash_addr, 256);
    ota_arch_read(ota_area_buf, flash_addr, 256);

    PRINTF("TEST_FLASH_PROCESS: OTA area buffer before write operation:\n");
    printBufferHex(ota_area_buf, 256);
    PRINTF("\n");

#if TEST_CLIENT
    ota_info_flash.fw_version = 1;
    ota_info_flash.crc = 1;
    ota_info_flash.fw_size = sizeof(ota_data);
    ota_info_flash.fw_fragment_num = ota_info_flash.fw_size / OTA_MAX_DATA_SIZE;
    ota_info_flash.fw_fragment_size = OTA_MAX_DATA_SIZE;
#else
    ota_info_flash.fw_version = 2;
    ota_info_flash.crc = 1;
    ota_info_flash.fw_size = sizeof(ota_data);
    ota_info_flash.fw_fragment_num = ota_info_flash.fw_size / OTA_MAX_DATA_SIZE;
    ota_info_flash.fw_fragment_size = OTA_MAX_DATA_SIZE;
#endif

    cur_len = 0;

    memcpy(&ota_write_buf[cur_len], &ota_info_flash.fw_version, sizeof(uint32_t));
    cur_len += sizeof(uint32_t);

    memcpy(&ota_write_buf[cur_len], &ota_info_flash.crc, sizeof(uint32_t));
    cur_len += sizeof(uint32_t);

    memcpy(&ota_write_buf[cur_len], &ota_info_flash.fw_size, sizeof(uint32_t));
    cur_len += sizeof(uint32_t);

    memcpy(&ota_write_buf[cur_len],&ota_info_flash.fw_fragment_num,sizeof(uint16_t));
    cur_len += sizeof(uint16_t);

    ota_write_buf[cur_len] = ota_info_flash.fw_fragment_size;
    cur_len++;

    print_ota_info_packet_status(&ota_info_flash);

    ota_arch_write(ota_write_buf, flash_addr, cur_len);
    ota_arch_read(ota_area_buf, flash_addr, 256);

    PRINTF("TEST_FLASH_PROCESS: OTA area buffer after write operation:\n");
    printBufferHex(ota_area_buf, 256);
    PRINTF("\n");

    last_ota_info = ota_parse_info_buf(ota_area_buf, 256);
    PRINTF("TEST_FLASH_PROCESS: OTA info packet status:\n");
    print_ota_info_packet_status(&last_ota_info);

    ota_arch_write(ota_data, flash_addr + FLASH_PAGE_SIZE, 128);
    ota_arch_read(ota_area_buf, flash_addr + FLASH_PAGE_SIZE, 128);

    PRINTF("TEST_FLASH_PROCESS: OTA area buffer OTA DATA:\n");
    printBufferHex(ota_area_buf, 128);
    PRINTF("\n");

    process_start(&request_process, NULL);

    PROCESS_END();
}

/*--------------------------------------------------------Thread(Request)----*/

PROCESS_THREAD(request_process, ev, data)
{
    // request timer, synch timer
    static struct etimer et_request;
    // static int counter_request = 0;
    static struct etimer et_identify;
    // init an ota packet
    static struct ota_packet p;
    // get size of ota packet
    static uint8_t udp_buf[MAX_PACKET_SIZE];
    // buffer len for outgoing packet
    static uint8_t buf_len = 0;

    PROCESS_BEGIN();
    PROCESS_PAUSE();
    // set synch timer and wait until node is synchronized.
    etimer_set(&et_identify, AUTHENTICATION_INTERVAL * CLOCK_SECOND);
    while (!foure_control.authenticated || default_instance == NULL || default_instance->current_dag->preferred_parent == NULL)
    {
        PROCESS_WAIT_UNTIL(etimer_expired(&et_identify));
        etimer_set(&et_identify, AUTHENTICATION_INTERVAL * CLOCK_SECOND);
        PRINTF("REQUEST_PROCESS: Waiting for synch...\n");
        watchdog_periodic();
    }

    // after the synchronization, get parent from default instance and get it's IP address.
    rpl_parent_t *parent = default_instance->current_dag->preferred_parent;
    parent_ip_address = rpl_get_parent_ipaddr(parent);

    // set the UDP connection with port UDP_PORT, check if the connection is available, if not, exit from process.
    if (!simple_udp_register(&udp_conn, UDP_PORT, NULL, UDP_PORT, udp_callback))
    {
        PRINTF("REQUEST_PROCESS: UDP Connection Error!\n");
        PROCESS_EXIT();
    }

    // PRINT DEBUG FOR TEST
    PRINTF("REQUEST_PROCESS: MAX_PACKET_SIZE is: %d\n", MAX_PACKET_SIZE);

    // set the request timer
    etimer_set(&et_request, REQUEST_SEND_INTERVAL * CLOCK_SECOND);
    while (1)
    {
        // control device ota_process_state, if ota_process_state is request, send request to parent
        if (ota_process_state == STATE_REQUEST)
        {
            // prepare request message, control if packet is prepared, if not, dont send packet
            if (prepare_ota_packet(&p, OTA_REQUEST))
            {
                buf_len = create_ota_packet(udp_buf, MAX_PACKET_SIZE, &p);
                // if packed is prepared, init a buffer of size ota packet and fill it with packet data, control if packet created, if not dont send packet
                if (buf_len > 0)
                {
                    PRINTF("CREATE_OTA_PACKET: Packet created. Packet is: \n");
                    printBufferHex(udp_buf, buf_len);
                    PRINTF("\n");
                    PRINTF("Packet is created with %d size. Sending to ", buf_len);
                    PRINT6ADDR(rpl_get_parent_ipaddr(default_instance->current_dag->preferred_parent));
                    PRINTF("\n");

                    PRINTF("1\n");
                    // send packet
                    simple_udp_sendto(&udp_conn, udp_buf, buf_len + 1, rpl_get_parent_ipaddr(default_instance->current_dag->preferred_parent));
                    PRINTF("2\n");
                }
                else
                    PRINTF("REQUEST_PROCESS: packet cannot created!\n");
            }
            else
                PRINTF("REQUEST_PROCESS: packet cannot prepared!\n");

            // send request message to parent
            PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et_request));
            etimer_reset(&et_request);
        }
        // if ota_process_state is STATE_UPDATE_CLIENT or STATE_UPDATE_SERVER, don't do anything, just wait until ota process ends.
        else if (ota_process_state == STATE_UPDATE_CLIENT || ota_process_state == STATE_UPDATE_SERVER)
        {
            // etimer_stop(&et_request);
            PRINTF("REQUEST_PROCESS: Device ota_process_state is %02X. So waiting for ota_process_state changing...\n", ota_process_state);
            process_start(&update_process, NULL);
            PROCESS_WAIT_EVENT_UNTIL(ota_process_state == STATE_REQUEST);
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
    // static struct ota_packet p;

    PROCESS_BEGIN();
    PROCESS_PAUSE();

    etimer_set(&et_update, PACKET_REQUEST_INTERVAL * CLOCK_SECOND);
    while (1)
    {
        if (ota_process_state == STATE_UPDATE_CLIENT)
        {
        }
        else if (ota_process_state == STATE_UPDATE_SERVER)
        {
            // wait for incoming requests
        }
        else
        {
            // unsupported state, wait or reset device?
        }

        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et_update));
        PRINTF("Hello World FROM UPDATE PROCESS\n");
        etimer_reset(&et_update);
    }

    ota_cell_num--;
    PROCESS_END();
}
/*-------------------------------------------------------------------Init----*/
void start_epidemic_ota()
{
    process_exit(&test_flash_process);
    process_start(&test_flash_process, NULL);
}